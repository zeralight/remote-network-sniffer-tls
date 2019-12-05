from scapy.all import *

# Generate 10 captures each of 8192 packets

for tcp in TCP(dport=list(range(1000, 1020))):
    pkts = [pkt for pkt in Ether() / IP(dst="127.0.0.0/20") / tcp]
    wrpcap("start{}.pcap".format(tcp.dport), pkts, append=True)
