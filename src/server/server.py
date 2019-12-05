import socket
import ssl
import threading
import logging
import sys
import traceback
import os
import datetime

import common


def write_pkts(f, received, protocol):
    if protocol == "pcap":
        recvdlen = len(received)
        offset = 0
        count = 0
        while offset + 8 < recvdlen:
            pktlen = int.from_bytes(received[offset+8:offset+12], "little")
            if offset + pktlen + 16 > recvdlen:
                break
            count += f.write(received[offset:offset+16+pktlen])
            offset += 16+pktlen
        return (received[offset:], count)
    else:
        count = f.write(received)
        return (b"", count)

def client_thread(conn, addr):
    logger.info("Connected to {}:{}".format(addr[0], addr[1]))
    try:
        protocol = conn.read(1)    
        if protocol not in (b"1", b"2"):
            raise IOError("invalid protocol " + str(protocol, "utf-8"))
    except IOError as e:
        logger.error("Couldn't read protocol from client. " + str(e))
        return

    if protocol == b"1":
        protocol = "pcap"
    else:
        protocol = "pcap.gz"
    
    client_dir = os.path.join(config["outputdir"], addr[0])
    try:
        os.makedirs(client_dir, mode=0o777, exist_ok=True)
    except OSError as e:
        logger.error("Couldn't create the output dir. " + str(e))
        sys.exit(-1)

    received = b""
    try:
        while True:
            written = 0
            try:
                cappath = os.path.join(client_dir, "{:%Y%m%d-%H%M%S.%f}".format(datetime.datetime.now())) + "." + protocol
                f = open(cappath, "wb+")
                if protocol == "pcap":
                    f.write(b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00')
                else:
                    f.write(b'\x1f\x8b\x08\x00\xe8;\xe0[\x02\xff\xbbrx\xd3B&\x06\x16\x06\x04`a`\x04\x92\x00!\xd9M>\x18\x00\x00\x00')
                
                while written < config['maxsize']:
                    chunk = conn.read(8192)
                    if chunk != None and chunk != b'':
                        received += chunk
                    (received, wrt) = write_pkts(f, received, protocol)
                    written += wrt
                    if chunk == None or chunk == b'':
                        logger.info(addr[0] + ": Stream closed")
                        return
            finally:
                logger.info(written)
                write_pkts(f, received, protocol)
                f.close()
                logger.info("Saved new capture to " + cappath)

    except Exception as e:
        traceback.print_exc()     
    finally:
        conn.close()




def main():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
            sock.bind((config["interface"], config["port"]))
            sock.listen(5)
            with context.wrap_socket(sock, server_side=True) as ssock:
                logger.info("Server started successfully to listen on {}:{}".format(config['interface'], config['port']))
                while True:
                    try:
                        conn, addr = ssock.accept()
                    except Exception as e:
                        logger.error('Could not authenticate client: ' + str(e))
                        continue
                    threading.Thread(target=client_thread, args=(conn, addr)).start()
    except Exception as e:
        logger.error('Could not bind to a interface or port: ' + str(e))

if __name__ == "__main__":
    cfgpath = "./server.ini"
    if len(sys.argv) < 2:
        print("No config path passed in parameter")
    else:
        cfgpath = sys.argv[1]
    print("Using config file: " + cfgpath)

    required_fields = {
        "client": [("trustedca", "string")],
        "server": [("interface", "string"), ("port", "int"), ("keypath", "string"), ("certpath", "string")]
    }

    optional_fields = {
        "server": [("logfile", "string", None), ("outputdir", "string", "."), ("maxsize", "int", 50)]
    }

    try:
        config = common.parse(cfgpath, required_fields, optional_fields)
    except Exception as e:
        print(str(e), file=sys.stderr)
        sys.exit(-1)
    
    config["maxsize"] *= 1024*1024

    logger = common.getLogger(logfile=config['logfile'])
    context = common.getContext(protocol=ssl.PROTOCOL_TLS_SERVER, certpath=config['certpath'], trustedca=config['trustedca'], keypath=config['keypath'])

    logger.info("parsed config: ")
    for k, v in config.items():
        logger.info("{}: {}".format(k, v))

    main()