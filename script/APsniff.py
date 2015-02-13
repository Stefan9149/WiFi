from scapy.all import *
import sys

pkts = rdpcap("../pkt/test3.cap")
target_ssid = str(sys.argv[1]) #"xfinitywifi"
unique_bssid = set()
target_channel = set()
eap_device = set()
crypto_scheme = []

def GetPackets(pkts):
	index = 0
	for pkt in pkts:
		if pkt.haslayer(EAPOL) or pkt.haslayer(EAP):
			eap_device.add(pkt[Dot11].addr3)
		if pkt.haslayer(Dot11Elt):
			layer = pkt[Dot11Elt]
			if layer.ID == 0 and layer.info == target_ssid:
				#print "Find at packet: %s" % index
				#print "Packet[%s]: " % index
				GetInfo(pkt)
		index += 1

def GetInfo(pkt):
	bssid = pkt[Dot11].addr3
	if bssid != "ff:ff:ff:ff:ff:ff":
		capability = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
			"{Dot11ProbeResp:%Dot11ProbeResp.cap%}")
		crypto = set()
		channel = None
		layer = pkt
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
		#update
		if bssid not in unique_bssid:
			unique_bssid.add(bssid)
		if channel != None and channel not in target_channel:
			target_channel.add(channel)
		if crypto not in crypto_scheme:
			crypto_scheme.append(crypto)
		#print crypto

def main(argv):
	if len(sys.argv) == 1:
		print "Python APsniff <ssid>"
		sys.exit()
	GetPackets(pkts)
	has_eap = False
	print ("Information for AP: '%s'" % target_ssid)
	print ("BSSID: ")
	for item in unique_bssid:
		if item in eap_device:
			has_eap = True
		print("%s" % item)
	print ("channel: ")
	for item in target_channel:
		print("%s" % item)
	print ("Encryption: ")
	for item in crypto_scheme:		        
		print("%s" % '/'.join(item))
	print ("EAP: ")
	if has_eap == True:
		print("Enabled")
	else:
		print("Not proved")


if __name__ == "__main__":
	main(sys.argv)
