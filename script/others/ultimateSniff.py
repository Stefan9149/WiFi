#! /usr/bin/env python
from scapy.all import *
from datetime import datetime
import sys
import time

pkts = rdpcap("../../pkt/test1.cap")
found = {}

def sniffWiFi(pkts):
	for p in pkts:
		if p.haslayer(Dot11) and p.type == 0 and p.subtype == 0x08 and hasattr(p, 'info'):
			ssid = ( len(p.info) > 0 and p.info != "\x00" ) and p.info or '<hidden>'
			probe = { "ssid" : ssid, "mac": p.addr2 }
			key = "%s_%s" % (ssid, p.addr2)
			found[key] = probe

sniffWiFi(pkts)

with open('output.txt', 'a') as f:
	f.write(",".join(["ssid", "mac"]) + "\r\n")
	for key in found:
		f.write(",".join(['"%s"' % x for x in [found[key]['ssid'], found[key]['mac']]]) + "\r\n")
