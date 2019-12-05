from scapy.all import *

# Generate 1000 captures each of 128 packets

for tcp in TCP(dport=list(range(1000, 2000))):
    pkts = [pkt for pkt in Ether() / IP(dst="127.0.0.0/24") / tcp]
    wrpcap("input/start{}.pcap".format(tcp.dport), pkts, append=True)
