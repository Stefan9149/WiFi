import subprocess
import time
from glob import glob

subprocess.Popen("rm " + "-r " + "/tmp/*.cap", shell = True)
p = subprocess.Popen("airport "+"en0 "+"sniff", shell = True)
time.sleep(5)
subprocess.Popen("kill -HUP %s" % p.pid, shell = True)
#print "finish"
pcapfile = glob("/tmp/*.cap")
subprocess.Popen("mv " + pcapfile[0] + " ../pkt/temp.cap", shell = True)
