#https://thepacketgeek.com/scapy/building-network-tools/part-06/
#sudo pip3 install Scapy
#sudo pip3 install matplotlib
#sudo pip3 install PyX

# sudo python3 ICMP-Scan.py

from scapy.all import *

while(1):
	p = sniff(count=10,filter="icmp")
	print(p)
	print(ls(IP))
	print(ls(ICMP))
