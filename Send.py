from scapy.all import *
import os

my_IP = os.popen("ifconfig").read().split("inet addr:")[1].strip().split(' ')[0]
my_MAC = os.popen("ifconfig").read().split("HWaddr")[1].strip().split(' ')[0]

ARP_pkt = ARP() # It means ARP_pkt is ARP packet
ARP_pkt.op = 2 # It means ARP Reply
ARP_pkt.psrc = "192.168.123.123" # It means source IP Address
ARP_pkt.pdst = "127.0.0.1" # It means Destination IP Address
ARP_pkt.hwdst = "12:34:56:78:90:ab" # It means Destination MAC Address
send(ARP_pkt) # It means sending ARP packet

data = "Hacked by 34t3rnull"
TCP_pkt = IP()/TCP()/Raw(load=data) # It means TCP_pkt is TCP packet and TCP_pkt's data is "Hacked by 34t3rnull" (Including IP protocol)
TCP_pkt.version = 4 # It means TCP_pkt's IP version is IPv4
TCP_pkt.src = "192.168.123.123" # It means Source IP Address
TCP_pkt.dst = "127.0.0.1" # It means Destination IP Address
TCP_pkt.sport = 80 # It means Source Port number
TCP_pkt.dport = 12345 # It means Destination Port number
del TCP_pkt.chksum # For vanishing the error (IP packet)
del TCP_pkt.len # For vanishing the error (IP packet)
send(TCP_pkt) # It means sending TCP packet


UDP_pkt = IP()/UDP() # It means UDP_pkt is UDP packet (Including IP protocol)
UDP_pkt.version = 4 # It means UDP_pkt's IP version is IPv4
UDP_pkt.src = "192.168.123.123" # It means Source IP Address
UDP_pkt.dst = "127.0.0.1" # It means Destination IP Address
del UDP_pkt.chksum # For vanishing the error (UDP, IP packet)
del UDP_pkt.len # For vanishing the error (UDP, IP packet)
send(UDP_pkt) # It means sending UDP packet