from scapy.all import *
import collections

pkts = rdpcap("../pkt/test1.cap")

unique_ap = {}
f = open('ssid', 'w')

def GetSSID(pkts):
	index = 0
	for pkt in pkts:
		#layers before Dot11Elt
		try:
			mac = pkt.addr2  # MAC[Dot11] 
			bssid = pkt[Dot11].addr3
			capability = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}{Dot11ProbeResp:%Dot11ProbeResp.cap%}")
			crypto = set()
			ssid, channel = None, None
		except AttributeError:
			pass
		if pkt.haslayer(Dot11Elt):
			layer = pkt[Dot11Elt]
			if layer.ID == 0:
				valid = True
				ssid = layer.info
				for ch in ssid:
					try:
						ch.decode('ascii')
					except UnicodeDecodeError:
						valid = False
						break
				if valid and bssid != None and bssid != "ff:ff:ff:ff:ff:ff" and bssid not in unique_ap and len(ssid) > 0:
					channel = None
					while Dot11Elt in layer:
						if layer.ID == 3 and len(layer.info) == 1:
							channel = int( ord(layer.info))
						if layer.ID == 48:
							crypto.add("WPA2")
						if layer.ID == 221 and layer.info.startswith('\x00P\xf2\x01\x01\x00'):
							crypto.add("WPA")
						layer = layer.payload
					if not crypto:
						if 'privacy' in capability:
							crypto.add("WEP")
						else:
							crypto.add("OPEN")
					probe = {"Packet No.": index, "SSID": ssid, "BSSID": bssid, "Capability":capability, "Channel": channel, "Encryption": ' / '.join(crypto)}
					key = "%s_%s" % (ssid, bssid)
					unique_ap[key] = probe
		index += 1

GetSSID(pkts)

od = collections.OrderedDict(sorted(unique_ap.items()))

with open('output2.txt', 'w') as out:
	out.write(",".join(["Packet No.", "SSID", "BSSID(MAC)", "Capability", "Channel", "Encryption"]) + "\r\n")
	for key in od:
	        out.write(",".join(['"%s"' % x for x in [od[key]['Packet No.'], od[key]['SSID'], od[key]['BSSID'], od[key]['Capability'],od[key]['Channel'], od[key]['Encryption']]]) + "\r\n")





