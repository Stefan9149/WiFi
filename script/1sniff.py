from scapy.all import *
import collections

pkts = rdpcap("../../pkt/test1.cap")

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
						if layer.ID > 3:
							break
						layer = layer.payload
					probe = {"Packet No.": index, "SSID": ssid, "BSSID": bssid, "Capability":capability, "Channel": channel}
					key = "%s_%s" % (ssid, bssid)
					unique_ap[key] = probe
			#elif pkt.ID == 3: #ID = DSset (channel)
				#print index
			#	if len(pkt.info) == 1: 
			#		channel = int( ord(pkt.info))
			#		unique_ap[key].update({"Channel": channel})
				#print index
			#elif pkt.ID > 3:
			#	unique_ap[key].update({"Channel": 0})
			#	break
       	     	#	pkt = pkt.payload
			#layerCount += 1
		index += 1

GetSSID(pkts)

od = collections.OrderedDict(sorted(unique_ap.items()))

with open('output.txt', 'w') as out:
	out.write(",".join(["Packet No.", "SSID", "BSSID(MAC)", "Capability", "Channel"]) + "\r\n")
	for key in od:
	        out.write(",".join(['"%s"' % x for x in [od[key]['Packet No.'], od[key]['SSID'], od[key]['BSSID'], od[key]['Capability'],od[key]['Channel']]]) + "\r\n")





