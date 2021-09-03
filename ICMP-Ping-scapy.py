#https://thepacketgeek.com/scapy/building-network-tools/part-06/
#sudo pip3 install Scapy
#sudo pip3 install matplotlib
#sudo pip3 install PyX

# sudo python3 ICMP-Scan.py

from scapy.all import *

DOMAIN_DST = "google.com"
pingr = IP(dst=DOMAIN_DST)/ICMP()
response = srloop(pingr, count=5)
print(response[0].summary())

