import sys
import socket
import ssl
import logging
import pcapy
import time
import threading
import datetime
import traceback
import signal
import os
import tempfile
import gzip
import configparser
import re

import common


__ENVIRONMENT__ = "prod"
#__ENVIRONMENT__ = "test"

class Client:
    """
    Map-Reduce based implementation to collect frames from multiple interfaces.
    it is impossible with pcapy to send data without dumping it before in a local pcap file
        eth0 ---> sniff ---> eth0.pcap (local) ------> collect ------
                                                                    |
                                        [when collected enough data]|-----> (eth0 + wlan0) frames --> server 
                                                                    |
        wlan0 --> sniff ---> wlan0.pcap (local) ------> collect -----
    """
    pcaphdr = b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00'
    pcap_gzip_hdr = b'\x1f\x8b\x08\x00\xe8;\xe0[\x02\xff\xbbrx\xd3B&\x06\x16\x06\x04`a`\x04\x92\x00!\xd9M>\x18\x00\x00\x00'

    def __init__(self, config):
        try:
            self._logger = common.getLogger(logfile=config['logfile'])
        except IOError as error:
            self._logger = common.getLogger()
            self._logger.warning("Couldn't setup logfile: " + str(error))

        self._logger.info("parsed config: ")
        for k, v in config.items():
            self._logger.info("{}: {}".format(k, v))
        
        if sys.byteorder == "big":
            self._logger.error("Unsupported architecture. Can send captures only in little-end format")
            sys.exit(-1)
        
        self._protocol = config["protocol"]
        self._promiscious = config["promiscious"]
        self._usb = config["non-network-devices"]

        try:
            self.available_devices = pcapy.findalldevs()
        except pcapy.PcapError as e:
            self._logger.error(str(e))
            sys.exit(-1)

        self._caps = self.load_caps(config["interfaces"])
        if self._caps == []:
            self._logger.info("Not listening to any interface. Exiting")
            sys.exit(-1)
        
        try:
            self.context = common.getContext(protocol=ssl.PROTOCOL_TLS_CLIENT, certpath=config['certpath'], trustedca=config['trustedca'], keypath=config['keypath'])
        except IOError as error:
            self._logger.error('Failed to initialize PKI infrastructure: ' + str(error) + ". Exiting")
            sys.exit(-1)
        
        self._minframes = config["minframes"]
        self._minsize = config["minsize"]

        self.data = b''

        self._lock = threading.Lock()
        self._condition_to_send = threading.Condition(self._lock)
        self._available_bytes = 0
        self._available_frames = 0

        self._sock = None
        self._ssock = None
        self._sniffing_threads = [threading.Thread(name="Sniffer " + cap[1], target=self.sniff, args=(cap[0],)) for cap in self._caps]
        self._alive_sniffing_threads = len(self._sniffing_threads)
        
        self.server_up = threading.Event() # blocks the sniffing threads when the server is down
        self._exit = threading.Event() # to stop the process

    def load_caps(self, interfaces):
        caps = []
        if any(x == "any" for x in interfaces):
            if self._usb: 
                interfaces = ["any"]
            else:
                interfaces = [x for x in self.available_devices if not(x.startswith("usb") or x == "nflog" or x == "nfqueue" or x == "any")]
        for interface in interfaces:
            try:
                if interface in self.available_devices:
                    cap = pcapy.open_live(interface, 65536, int(self._promiscious), 0)
                else:
                    cap = pcapy.open_offline(interface)
                caps.append((cap, interface))
                self._logger.info("Listening to " + interface)
            except pcapy.PcapError as e:
                self._logger.error(str(e))
        
        return caps


    def start(self):
        self._logger.info("Client started: ctrl^c to stop")
        for th in self._sniffing_threads:
            th.start()
        try:
            timeout = 0
            while True:
                time.sleep(timeout)
                self._logger.info("Connecting..")
                try:
                    with socket.create_connection((config['host'], config['port']), 5) as self._sock:
                        with self.context.wrap_socket(self._sock) as self._ssock:
                            timeout = 0
                            if self._protocol == "pcap": self._ssock.sendall(b"1")
                            else: self._ssock.sendall(b"2")
                            self.server_up.set() # Reactive sniffing and sending threads
                            self._logger.info("Established connection with the server")
                            self.start_sending()
                            self._logger.info("No more captures to process. Exiting")
                            sys.exit(0)
                except ssl.SSLError as e:
                    self._logger.error("TLS Error: " + str(e))
                    traceback.print_exc()
                except socket.error as e:
                    self._logger.error("Couldn't establish a connection to the server: " + str(e))

                timeout = min(60*3, 2*timeout+1)
                self._logger.info("Next connection attempt is after {}mn {}s".format(timeout//60, timeout%60))
                self.server_up.clear() # Pausing sniffing and sending threads
        except (KeyboardInterrupt, SystemExit):
            self._logger.info("Received Keyboard interruption or kill signal: Exiting")
            os.kill(os.getpid(), signal.SIGKILL)


    def start_sending(self):
        while True:
            with self._condition_to_send:
                while not self.ready_to_send():
                    self._condition_to_send.wait()

                if self._protocol == "pcap.gz":
                    self.data = gzip.compress(self.data)
                
                
                # Send to server
                while not self.server_up.isSet():
                    self.server_up.wait()

                if __ENVIRONMENT__ == "test":
                    filename = "{:%Y%m%d-%H%M%S.%f}".format(datetime.datetime.now()) + "." + self._protocol
                    f = open(filename, "wb")
                    if self._protocol == "pcap":
                        f.write(Client.pcaphdr + self.data)
                    else:
                        f.write(Client.pcap_gzip_hdr + self.data)
                    f.close()

                sent = self._ssock.send(self.data)
                self.data = self.data[sent:]
                self._logger.info("Sent {} bytes".format(sent))
                
                
                if self._alive_sniffing_threads == 0: # no more packets to process
                    break
                self.data = b''
                self._available_frames = 0
                self._available_bytes = 0
                

    ready_to_send = lambda self: (self._available_bytes >= self._minsize and self._available_frames >= self._minframes) or (self._alive_sniffing_threads == 0)


    def update_data(self, hdr, pkt):
        with self._lock:
            if hdr == None:
                self._alive_sniffing_threads -= 1
                #self._logger.info(threading.current_thread().getName() + " Reducing alive_sniffing_threads to " + str(self._alive_sniffing_threads))
            else:
                hdr_bytes = b''.join([x.to_bytes(4, 'little') for x in [hdr.getts()[0], hdr.getts()[1], hdr.getlen(), hdr.getcaplen()]])
                self.data += hdr_bytes + pkt
                self._available_frames += 1
                self._available_bytes += hdr.getlen()

            if self.ready_to_send():
                #self._logger.info(threading.current_thread().getName() + " Updating data")
                self._condition_to_send.notify()
    

    def sniff(self, cap):
        while True:
            while not self.server_up.isSet():
                self.server_up.wait()
            try:
                hdr, pkt = cap.next()
                self.update_data(hdr, pkt)
                if hdr == None:
                    #self._logger.info(threading.current_thread().getName() + " Finished job")
                    break
            except pcapy.PcapError as e:
                self._logger.debug(str(e))


if __name__ == "__main__":
    cfgpath = "./client.ini"
    if len(sys.argv) < 2:
        print("No config path passed in parameter")
    else:
        cfgpath = sys.argv[1]
    print("Using config file: " + cfgpath)

    required_fields = {
        "client": [("keypath", "string"), ("certpath", "string"), ("interfaces", "string")],
        "server": [("host", "string"), ("port", "int"), ("trustedca", "string")]
    }

    optional_fields = {
        "client": [("minsize", "int", 0), ("minframes", "int", 1), ("non-network-devices", "boolean", False),
            ("promiscious", "boolean", False), ("logfile", "string", None), ("protocol", "string", "pcap")]
    }

    config = common.parse(cfgpath, required_fields, optional_fields)
    config["interfaces"] = re.sub(' +', ' ', config["interfaces"].strip()).split(' ')
    config["minsize"] *= 1024

    Client(config).start()