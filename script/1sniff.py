from scapy.all import *
import collections

pkts = rdpcap("../pkt/test3.cap")

unique_ap = {}
f = open('ssid', 'w')
hidden_ssid = set()
eapol = set()

def GetSSID(pkts):
	index = 0
	for pkt in pkts:
		#layers before Dot11Elt
		try:
			mac = pkt.addr2  # MAC[Dot11] 
			bssid = pkt[Dot11].addr3
			capability = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
					"{Dot11ProbeResp:%Dot11ProbeResp.cap%}")
			crypto = set()
			ssid, channel = None, None
			if pkt.haslayer(EAPOL) and bssid not in eapol:
				eapol.add(bssid)
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
						if ch < ' ' or ch > '~':
							valid = False
					except UnicodeDecodeError:
						valid = False
						break
				if len(ssid) > 0 and valid and bssid != None and bssid != "ff:ff:ff:ff:ff:ff" and bssid not in unique_ap:
					#if len(ssid) == 0: 
					#	if bssid not in hidden_ssid:
					#		hidden_ssid.add(bssid)
					#		ssid = "<Hidden>"
					#	else:
					#		continue
					while Dot11Elt in layer:
						if layer.ID == 3 and len(layer.info) == 1:
							channel = int( ord(layer.info))
						if layer.ID == 48:
							crypto.add("WAP2")
						if layer.ID == 221 and layer.info.startswith('\x00P\xf2\x01\x01\x00'):
							crypto.add("WPA")
						layer = layer.payload
					if not crypto:
						if 'privacy' in capability:
							crypto.add("WEP")
						else:
							crypto.add("OPEN")
					probe = {"Packet No.": index, "SSID": ssid, "BSSID": bssid, 
							"Capability":capability, "Channel": channel, "Encryption": ' / '.join(crypto)}
					key = "%s_%s" % (ssid, bssid)
					unique_ap[key] = probe
		index += 1

GetSSID(pkts)

od = collections.OrderedDict(sorted(unique_ap.items()))

with open('output.txt', 'w') as out:
	out.write(",".join(["Packet No.", "SSID", "BSSID(MAC)", "Capability", "Channel", "Encryption"]) + "\n")
	for key in od:
	        out.write(",".join(['"%s"' % x for x in [od[key]['Packet No.'], od[key]['SSID'], od[key]['BSSID'], od[key]['Capability'],od[key]['Channel'], od[key]['Encryption']]]) + "\n")
	out.write("Hidden SSID: \n")
	for item in hidden_ssid:
		out.write("%s\n" % item)
	out.write("EAPoL Enabled: \n")
	for item in eapol:
		out.write("%s\n" % item)





