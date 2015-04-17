import sys
import subprocess
import time
import csv

AIRPORT_PATH = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
#HashMap for Risk Rating
configure_to_threat = {}

def loadMaping(configure_to_threat):
	f = open('ThreatsData.csv')
	csv_f = csv.reader(f)
	for row in csv_f:
		scanning = map(int, row[1:5])	#exclude DisconnectOnLogout
		threats = map(float, row[5:10])
		key = str(row[1])+str(row[2])+str(row[3])+str(row[4])  
		#print key
		configure_to_threat[key] = threats

def callScanAll():
	p = subprocess.Popen(AIRPORT_PATH + " -s", stdout = subprocess.PIPE, shell = True)
	out, err = p.communicate()
	print str(out)

def callScanAP(target, extra):
	p = subprocess.Popen(AIRPORT_PATH + " -s " + target, stdout = subprocess.PIPE, shell = True)
	out, err = p.communicate()
	print str(out)
	if(out == "No networks found\n"):
		sys.exit()
	print "Evaluating the Access Point...\n"
	evaluation(out, extra)

def callConnectedAP():
	p = subprocess.Popen(AIRPORT_PATH + " -I", stdout = subprocess.PIPE, shell = True)
	out, err = p.communicate()
	print str(out)

def printHelp():
	print "Usage: python newAPsniff.py <options> <subOptions> \n"
	print "<option> = --all/-a\t(Show All Access Points)"
	print "<option> = --target/-t, [argument] = [ssid of AP]\t(Scan a target Access Points)"
	print "<option> = --info/-i\t(Show info of current connected Access Points)"
	#print "[option] = -c, [argument] = ssid of AP\t(Connect to Access Points)"
	#print "[option] = -d\t(Disconnect from Access Points)"


def getLocalWiFiConfig(scanning):
	disconnectOnLogout = False
	joinMode = False
	joinModeFallback = False
	p = subprocess.Popen(AIRPORT_PATH + " prefs disconnectonlogout", stdout = subprocess.PIPE, shell = True)
	out, err = p.communicate()
	if(out.split("=")[1] == "NO\n"):
		disconnectOnLogout = False
	else:
		disconnectOnLogout = True

	p = subprocess.Popen(AIRPORT_PATH + " prefs joinmode", stdout = subprocess.PIPE, shell = True)
	out, err = p.communicate()
	if(out.split("=")[1] == "Unknown\n"):
		joinMode = False
	else:
		joinMode = True   #no matter which one among Automatic/Preferred/Ranked/Recent/Strongest
	
	p = subprocess.Popen(AIRPORT_PATH + " prefs joinmodefallback", stdout = subprocess.PIPE, shell = True)
	out, err = p.communicate()
	if(out.split("=")[1] == "DoNothing\n"):
		joinModeFallback = False
	else:
		joinModeFallback = True   #no matter which one among Prompt/JoinOpen/KeepLooking

	if disconnectOnLogout == False:
		scanning[0] = 1
	else:
		scanning[0] = 0

	if joinMode == False and joinModeFallback == False:
		scanning[1] = 0
	elif joinMode == False or joinModeFallback == False:
		scanning[1] = 1
	else:
		scanning[1] = 2
	return

def checkRoot(scanning):
	print "(Ignore by pressing 'Enter' if there is any password prompts)"
	p = subprocess.Popen("ssh" + " 127.0.0.1", stdout = subprocess.PIPE, stderr=subprocess.PIPE, shell = True)
	result = p.stdout.readlines()
	enableSSH = False
	if result == []:
		error = p.stderr.readlines()
		if error[0].split()[0] == "ssh:":
			enableSSH = False
		else: 
			enableSSH = True
	else:
		enableSSH = True
	if enableSSH == True:
		scanning[2] = 1
	else:
		scanning[2] = 0

def checkHidden(target): #not shown, run at background
	p = subprocess.Popen(AIRPORT_PATH + " -s", stdout = subprocess.PIPE, shell = True)
	out, err = p.communicate()
	p2 = subprocess.Popen(AIRPORT_PATH + " -s", stdout = subprocess.PIPE, shell = True)
	out2, err2 = p2.communicate()
	if target in out or target in out2:
		return False
	else:
		return True

def checkSSIDVendor(ssid):
	f = open('ssid.csv')
	ssid_f = csv.reader(f)
	for row in ssid_f:
		if row[0] in ssid:
			return True
	return False

def evaluation(info, extra):
	#info from AP
	output = str(info).split()
	scanning = [0,0,0,1,0]
	parameters = "" #Auto-Connection, Root Privilege, SSID, Authentication/Encryption
	ssid = output[8+extra]
	bssid = output[9+extra]
	security = 0
	#Authentication/Encryption
	#print output[14+extra]
	if output[14+extra] != "NONE":
		if output[14+extra].split("(")[0] == "WPA2":
			security = 4
		elif output[14+extra].split("(")[0] == "WPA" and len(output) > 15+extra and output[15+extra].split("(")[0] == "WPA2":
			security = 3
		elif output[14+extra] == "WPA":
			security = 2
		elif output[14+extra] == "WEP":
			security = 1
		else:
			security = 0
	scanning[4] = security
	#get auto-connection/disconnection configurations
	getLocalWiFiConfig(scanning)
	#get ssh remote login configuration
	checkRoot(scanning)
	#get ssid property: hidden/public/info+
	hidden = checkHidden(ssid)
	if hidden == True:
		scanning[3] = 0
	else:
		if checkSSIDVendor(ssid) == True:
			scanning[3] = 2
		else:
			scanning[3] = 1
	#Get score from mapping data
	key = str(scanning[1])+str(scanning[2])+str(scanning[3])+str(scanning[4])
	print scanning
	threats = configure_to_threat[key]
	#print scanning
	printScore(threats, scanning[0])

#Print Risk Rating Result given threat vectors
def printScore(threats, factor):
	threatName = ["Sniffing\t\t", "Fake Access Point\t", \
	"Break WLAN Auth\t", "Hotspot Evil Twin\t", \
	"Cracking Password\t"]
	sum = 0
	count = 0
	for threat in threats:
		print "["+str(count+1)+"] [Threat] " + str(threatName[count]) + " [Score]: " + str(threat*(1 + factor*0.1)) + "/100 "\
				+ "\t[Severity]: " + str(calRank(threat*(1 + factor*0.1)))
		sum += threat*(1 + factor*0.1)
		count = count + 1
	print "\nTotal Risk Rating: [Score]: " + str(sum/5) + "/100\t" +"[Severity]: "+ str(calRank(sum/5))

#Detailed Explanation for Risk Rating
#def showDetails():

#Calculate Ranking given score
def calRank(score):
	if score>=0 and score < 20:
		return "D"
	elif score>=20 and score < 40:
		return "C"
	elif score>=40 and score < 60:
		return "B"
	elif score>=60 and score < 80:
		return "A"
	else:
		return "S"

def main(argv):
	if len(argv) == 1:
		printHelp()
		sys.exit()

	loadMaping(configure_to_threat)

	option = str(sys.argv[1])
	if option == "--all" or option == "-a":
		callScanAll()
	elif option == "--target" or option == "-t":
		argvSize = len(argv)
		if argvSize == 2:
			print "No target ssid was given, try again"
			sys.exit()
		if argv[2][0] != '[' or argv[argvSize-1][len(argv[argvSize-1])-1] != ']':
			print "bad format, ssid should be embraced by [ ]"
			sys.exit()
		index = 2
		target = ""
		while index < argvSize:
			target = target + " " + argv[index]
			index = index + 1
		target = '"' + target[2:len(target)-1] + '"'
		extra = argvSize - 3  #for cases that ssid includes spaces.
		callScanAP(target, extra)
	elif option == "--info" or option == "-i":
		callConnectedAP()
	else:
		printHelp()


if __name__ == "__main__":
	main(sys.argv)

