from Tkinter import *
import ttk
import sys
import subprocess
import time
import csv
import StringIO
import tkMessageBox
import threading

AIRPORT_PATH = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
#HashMap for Risk Rating

class Application(Frame):

    def resetLogo(self):
        self.logo_pic = PhotoImage(file="../images/logo.png")
        self.logo = Label(self, image = self.logo_pic)
        self.logo.grid({"row": 2, "column":0})

    def setLogo(self, severity):
        filename = "../images/logo_" + severity + ".png"
        self.logo_pic = PhotoImage(file=filename)
        self.logo = Label(self, image = self.logo_pic)
        self.logo.grid({"row": 2, "column":0})

    def createWidgets(self):
        self.logo_pic = PhotoImage(file="../images/logo.png")
        self.logo = Label(self, image = self.logo_pic)
        self.logo.grid({"row": 2, "column":0})


        self.button1 = Button(self, text="Help", command = self.introduction)
        self.button1.grid({"row":1, "column":0})
        self.button2 = Button(self, text="Scan Wi-Fi Nearby", command = self.callScanAll)
        self.button2.grid({"row":0, "column":1})
        self.button3 = Button(self, text="Evaluate A Target", command = self.callScanAP)
        self.button3.grid({"row":1, "column":1})
        self.button4 = Button(self, text="Connected Wi-Fi Info", command = self.callConnectedAP)
        self.button4.grid({"row":6, "column":1})

        self.button5 = Button(self, text="Detail Report", command = self.detailReport)
        self.button5.grid({"row":3, "column":0})
        self.button6 = Button(self, text="Mitigation Suggestions", command = self.mitigationSuggestion)
        self.button6.grid({"row":6, "column":0})


        self.list_ap = Listbox(self, height = 14, width = 22)
        self.list_ap.grid({"row": 2, "column": 1})
        self.list_ap.bind("<<ListboxSelect>>", self.on_select)

        self.list_info = Listbox(self, height = 8, width = 30)
        self.list_info.grid({"row": 4, "column": 1})

        self.list_evaluation = Listbox(self, height = 8, width = 30)
        self.list_evaluation.grid({"row": 4, "column": 0})


        self.label5 = Label(self, text = "Risk Evaluation Result")
        self.label5.config(bg = 'lightgrey')
        self.label5.grid({"row":5, "column":0})
        self.label3 = Label(self, text = "Version: 1.0 beta")
        self.label3.grid({"row": 0, "column": 0})
        self.label1 = Label(self, text = "Wi-Fi List")
        self.label1.config(bg = 'lightgrey')
        self.label1.grid({"row": 3, "column": 1})
        self.label4 = Label(self, text = "Wi-Fi Details")
        self.label4.config(bg = 'lightgrey')
        self.label4.grid({"row": 5, "column": 1})
        self.label2 = Label(self, text = "Lei Shao #CS6266 INFS Practicum#\nApr, 2015", font=('times', 10))
        self.label2.config(font=('times', 10, 'italic'))
        self.label2.grid({"row": 7, "column": 1})

    def on_select(self, evt):
        self.resetLogo()
        index = evt.widget.curselection()[0]
        self.target = self.list_ap.get(index)
        detail = self.cache_scan_all.get(self.target)
        self.list_info.delete(0, END)
        self.list_evaluation.delete(0, END)
        buf = detail.split("\n")
        self.list_info.insert(END, "SSID:"+buf[0])
        self.list_info.insert(END, "BSSID:"+buf[1])
        self.list_info.insert(END, "RSSI:"+buf[2])
        self.list_info.insert(END, "CHANNEL:"+buf[3])
        self.list_info.insert(END, "HT:"+buf[4])
        self.list_info.insert(END, "CC:"+buf[5])
        self.list_info.insert(END, "SECURITY:"+buf[6])
        if len(buf) == 9:
            self.list_info.insert(END, "SECURITY:" + buf[7])

    def introduction(self):
        intro = """WiFi Scout\nA simple program designed to help user be aware of potential risks from wireless networks by giving specific evaluation reports, and suggesting mitigation methods"""
        tkMessageBox.showinfo("Introduction", intro, parent = self, icon = "question")

    def callConnectedAP(self):
        p = subprocess.Popen(AIRPORT_PATH + " -I", stdout = subprocess.PIPE, shell = True)
        out, err = p.communicate()
        tmp = str(out).split("\n")
        output = ""
        for row in tmp:
            output = output + row.strip() + "\n"
        tkMessageBox.showinfo("Introduction", output, parent = self, icon = "question")


    def callScanAll(self):
        self.resetLogo()
        self.target = ""
        p = subprocess.Popen(AIRPORT_PATH + " -s", stdout = subprocess.PIPE, shell = True)
        out, err = p.communicate()
        buf = out.split("\n")
        self.list_ap.delete(0, END)
        i=1
        for row in buf:
            if i == 1:
                i = i+1
                continue
            tmp = row.strip().split()
            if len(tmp) == 0:
                break
            ssid = tmp[0]
            index = 1
            while len(tmp[index]) >2 and tmp[index][2] != ':':
                ssid = ssid + ' ' + tmp[index]
                index = index + 1
            self.list_ap.insert(END, ssid)
            info = ""
            count = 0
            for str in tmp:
                if count < index - 1:
                    info = info + str + " "
                    count = count + 1
                else:
                    info = info + str + "\n"
            self.cache_scan_all[ssid] = info
            i=i+1

    def callScanAP(self):
        if len(self.target) == 0:
            tkMessageBox.showinfo("Warning", "You must choose a Wi-Fi as the target!!!", parent = self)
            return
        else:
            p = subprocess.Popen(AIRPORT_PATH + " -s " + self.target, stdout = subprocess.PIPE, shell = True)
            out, err = p.communicate()
            if out == "No networks found\n":
                tkMessageBox.showinfo("Error", "The Wi-Fi you chose could not be found any more. Refresh the list and retry", parent = self)
            else:
                print "Evaluating the Access Point...\n"
                extra = 0
                if len(self.target.split(" "))>1:
                    extra = len(self.target.split(" ")) - 1
                self.evaluation(out, extra)

    def evaluation(self, info, extra):
        self.list_evaluation.delete(0, END)
        #info from AP
        output = str(info).split()
        scanning = [0,0,0,1,0]
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
        self.getLocalWiFiConfig(scanning)
        #get ssh remote login configuration
        self.checkRoot(scanning)
        #get ssid property: hidden/public/info+
        hidden = self.checkHidden(ssid)
        if hidden == True:
            scanning[3] = 0
        else:
            if self.checkSSIDVendor(ssid) == True:
                scanning[3] = 2
            else:
                scanning[3] = 1
        #Get score from mapping data
        key = str(scanning[1])+str(scanning[2])+str(scanning[3])+str(scanning[4])
        #print scanning
        threats = self.configure_to_threat[key]
        self.globalScanning = scanning
        self.globalThreatsVectors = threats
        #print scanning
        self.printScore(threats, scanning[0])

    def getLocalWiFiConfig(self, scanning):
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

    def printScore(self, threats, factor):
        threatName = ["Sniffing\t\t", "Fake Access Point\t", \
        "Break WLAN Auth\t", "Hotspot Evil Twin\t", \
        "Cracking Password\t"]
        sum = 0
        count = 0
        threatSeverityVector = [False, False, False, False, False]
        for threat in threats:
            #print "["+str(count+1)+"] [Threat] " + str(threatName[count]) + " [Score]: " + str(threat*(1 + factor*0.1)) + "/100 "\
            #        + "\t[Severity]: " + str(self.calRank(threat))
            if self.calRank(threat*(1 + factor*0.1)) == "A" or self.calRank(threat*(1 + factor*0.1)) == "B" or self.calRank(threat*(1 + factor*0.1)) == "S":
                threatSeverityVector[count] = True
            sum += threat*(1 + factor*0.1)
            count = count + 1
        totalscore = sum/5
        severity = str(self.calRank(sum/5))
        #print "\nTotal Risk Rating: [Score]: " + str(sum/5) + "/100\t" +"[Severity]: "+ severity
        self.setLogo(severity)
        self.list_evaluation.insert(END, "[Score]: " + str(totalscore) + "/100, [Severity]: " + severity)
        self.list_evaluation.insert(END, "Highly Potential Threats: ")
        enum_threat = ["Sniffing", "Fake Access Point", "Break WLAN Point", "Hotspot Evil Twin", "Cracking Password"]
        index = 0
        while index < 5:
            if threatSeverityVector[index] == True:
                self.list_evaluation.insert(END, enum_threat[index] + ": [Severity " + str(self.calRank(threats[index]*(1 + factor*0.1))) +"]")
            index = index + 1

    def detailReport(self):
        if self.globalThreatsVectors == [0,0,0,0,0]:
            msg = """There is no available report produced, you should check detail report after choosing a target and evaluating it"""
            tkMessageBox.showinfo("Warning", msg, parent = self, icon = "question")
            return
        t = Toplevel(self)
        t.wm_title("Detail Report")
        ws = t.winfo_screenwidth()
        hs = t.winfo_screenheight()
        w = 680
        h = 560
        x = (ws/2) - (w/2)
        y = (hs/2) - (h/2)
        t.geometry('%dx%d+%d+%d' % (w, h, x, y))
        t.attributes("-topmost", True)
        self.child = t
        ####################################################################################
        t.logo_pic = PhotoImage(file="../images/logo_mini.png")
        t.logo = Label(t, image = t.logo_pic)
        t.logo.place(x=160, y=0)
        t.label1_1 = Label(t, text = "Detail Evaluation Report", font = ('black', 20, 'bold'), bg = 'grey')
        t.label1_1.place(x=225, y=5)
        t.logo2 = Label(t, image = t.logo_pic)
        t.logo2.place(x = 490, y = 0)
        ####################################################################################
        t.label2_1 = Label(t, text = "Target Wi-Fi Access Point:", font = ('times', 16))
        t.label2_1.place(x= 10, y = 50)
        t.label2_2 = Label(t, text = self.target, bg = 'lightgrey', font = ('black', 18))
        t.label2_2.place(x= 220, y = 50)
        ####################################################################################
        t.label3_1 = Label(t, text = "1. Evidences For Evaluation", font = ('times', 16, 'bold'))
        t.label3_1.place(x= 10, y = 70)
        ####################################################################################
        t.label4_1 = Label(t, text = "###Local Configurations###", font = ('times', 16, 'italic'))
        t.label4_1.place(x= 10, y = 90)
        ####################################################################################
        t.label5_1 = Label(t, text = "Auto-disconnection: ", font = ('times', 16, 'italic'), bg = 'lightblue')
        t.label5_1.place(x= 10, y = 120)
        t.button5_2 = Button(t, text = "Details", command = self.detailConfig1)
        t.button5_2.place(x=170, y = 120)
        t.label5_3 = Label(t, text = "Enabled ", font = ('times', 16))
        if self.globalScanning[0] == 1:
            t.label5_3.config(font = ('times', 16, 'italic'))
            t.label5_3.config(bg = 'green')
        t.label5_3.place(x= 250, y = 120)
        t.label5_4 = Label(t, text = "Disabled ", font = ('times', 16))
        if self.globalScanning[0] == 0:
            t.label5_4.config(font = ('times', 16, 'italic'))
            t.label5_4.config(bg = 'red')
        t.label5_4.place(x= 330, y = 120)  
        ####################################################################################
        t.label6_1 = Label(t, text = "Auto-connection: ", font = ('times', 16, 'italic'), bg = 'lightblue')
        t.label6_1.place(x= 10, y = 150)
        t.button6_2 = Button(t, text = "Details", command = self.detailConfig2)
        t.button6_2.place(x=170, y = 150)
        t.label6_3 = Label(t, text = "Both", font = ('times', 16))
        if self.globalScanning[1] == 2:
            t.label6_3.config(font = ('times', 16, 'italic'))
            t.label6_3.config(bg = 'red')
        t.label6_3.place(x= 250, y = 150)
        t.label6_4 = Label(t, text = "Either", font = ('times', 16))
        if self.globalScanning[1] == 1:
            t.label6_4.config(font = ('times', 16, 'italic'))
            t.label6_4.config(bg = 'yellow')
        t.label6_4.place(x= 330, y = 150)
        t.label6_5 = Label(t, text = "None", font = ('times', 16))
        if self.globalScanning[1] == 0:
            t.label6_5.config(font = ('times', 16, 'italic'))
            t.label6_5.config(bg = 'green')
        t.label6_5.place(x= 410, y = 150)
        ####################################################################################
        t.label7_1 = Label(t, text = "Remote Access: ", font = ('times', 16, 'italic'), bg = 'lightblue')
        t.label7_1.place(x= 10, y = 180)
        t.button7_2 = Button(t, text = "Details", command = self.detailConfig3)
        t.button7_2.place(x=170, y = 180)
        t.label7_3 = Label(t, text = "Enabled", font = ('times', 16))
        if self.globalScanning[2] == 1:
            t.label7_3.config(font = ('times', 16, 'italic'))
            t.label7_3.config(bg = 'red')
        t.label7_3.place(x= 250, y = 180)
        t.label7_4 = Label(t, text = "Disabled", font = ('times', 16))
        if self.globalScanning[2] == 0:
            t.label7_4.config(font = ('times', 16, 'italic'))
            t.label7_4.config(bg = 'green')
        t.label7_4.place(x= 330, y = 180)
        ####################################################################################
        t.label8_1 = Label(t, text = "###Access Point Configurations###", font = ('times', 16, 'italic'))
        t.label8_1.place(x= 10, y = 210)
        ####################################################################################
        t.label9_1 = Label(t, text = "Access Point's SSID: ", font = ('times', 16, 'italic'), bg = 'lightblue')
        t.label9_1.place(x= 10, y = 240)
        t.button9_2 = Button(t, text = "Details", command = self.detailConfig4)
        t.button9_2.place(x=170, y = 240)
        t.label9_3 = Label(t, text = "Hidden", font = ('times', 16))
        if self.globalScanning[3] == 0:
            t.label9_3.config(font = ('times', 16, 'italic'))
            t.label9_3.config(bg = 'green')
        t.label9_3.place(x= 250, y = 240)
        t.label9_4 = Label(t, text = "Public", font = ('times', 16))
        if self.globalScanning[3] == 1:
            t.label9_4.config(font = ('times', 16, 'italic'))
            t.label9_4.config(bg = 'yellow')
        t.label9_4.place(x= 330, y = 240)
        t.label9_5 = Label(t, text = "Info+", font = ('times', 16))
        if self.globalScanning[3] == 2:
            t.label9_5.config(font = ('times', 16, 'italic'))
            t.label9_5.config(bg = 'red')
        t.label9_5.place(x= 410, y = 240)
        ####################################################################################
        t.label10_1 = Label(t, text = "Encryption(Auth): ", font = ('times', 16, 'italic'), bg = 'lightblue')
        t.label10_1.place(x= 10, y = 270)
        t.button10_2 = Button(t, text = "Details", command = self.detailConfig5)
        t.button10_2.place(x=170, y = 270)
        ####################################################################################
        t.label11_1 = Label(t, text = "Open", font = ('times', 16))
        if self.globalScanning[4] == 0:
            t.label11_1.config(font = ('times', 16, 'italic'))
            t.label11_1.config(bg = 'red')
        t.label11_1.place(x= 250, y = 270)
        t.label11_2 = Label(t, text = "WEP", font = ('times', 16))
        if self.globalScanning[4] == 1:
            t.label11_2.config(font = ('times', 16, 'italic'))
            t.label11_2.config(bg = 'yellow')
        t.label11_2.place(x= 330, y = 270)
        t.label11_3 = Label(t, text = "WPA", font = ('times', 16))
        if self.globalScanning[4] == 2:
            t.label11_3.config(font = ('times', 16, 'italic'))
            t.label11_3.config(bg = 'green')
        t.label11_3.place(x= 410, y = 270)        
        t.label11_4 = Label(t, text = "WPA/WPA2", font = ('times', 14))
        if self.globalScanning[4] == 3:
            t.label11_4.config(font = ('times', 16, 'italic'))
            t.label11_4.config(bg = 'green')
        t.label11_4.place(x= 490, y = 270)
        t.label11_5 = Label(t, text = "WPA2", font = ('times', 16))
        if self.globalScanning[4] == 4:
            t.label11_5.config(font = ('times', 16, 'italic'))
            t.label11_5.config(bg = 'green')
        t.label11_5.place(x= 600, y = 270)
        ####################################################################################
        t.label12_1 = Label(t, text = "2. Evaluation Details: Potential Threats Risk Ratings", font = ('times', 16, 'bold'))
        t.label12_1.place(x= 10, y = 300)
        ####################################################################################
        t.label12_1 = Label(t, text = "Threat Name", font = ('times', 16, 'italic'))
        t.label12_1.place(x= 10, y = 330)
        t.label12_2 = Label(t, text = "Score(?/100)", font = ('times', 16, 'italic'))
        t.label12_2.place(x= 180, y = 330)
        t.label12_3 = Label(t, text = "Severity(S>A>B>C>D)", font = ('times', 16, 'italic'))
        t.label12_3.place(x= 330, y = 330)
        t.label12_4 = Label(t, text = "Details", font = ('times', 16, 'italic'))
        t.label12_4.place(x= 530, y = 330)
        ####################################################################################
        factor = 1 if self.globalScanning[0] == 0 else 0
        ####################################################################################
        t.label13_1 = Label(t, text = "Sniffing", font = ('times', 16, 'italic'), bg = 'lightblue')
        t.label13_1.place(x= 10, y = 360)
        t.label13_2 = Label(t, text = str(self.globalThreatsVectors[0] * (1+factor*0.1)), font = ('times', 16))
        t.label13_2.place(x= 200, y = 360)
        rank1 = self.calRank(self.globalThreatsVectors[0] * (1+factor*0.1))
        t.label13_3 = Label(t, text = str(rank1), font = ('times', 16, 'bold'))
        if rank1 == "S" or rank1 == "A":
            t.label13_3.config(bg = 'red')
        elif rank1 == "B":
            t.label13_3.config(bg = 'orange')
        elif rank1 == "C":
            t.label13_3.config(bg = 'yellow')
        else:
            t.label13_3.config(bg = 'green')
        t.label13_3.place(x= 400, y = 360)
        t.button13_4 = Button(t, text = "Details", command = self.detailTreat1)
        t.button13_4.place(x=530, y = 360)
        ####################################################################################
        t.label14_1 = Label(t, text = "Fake Access Point", font = ('times', 16, 'italic'), bg = 'lightblue')
        t.label14_1.place(x= 10, y = 390)
        t.label14_2 = Label(t, text = str(self.globalThreatsVectors[1] * (1+factor*0.1)), font = ('times', 16))
        t.label14_2.place(x= 200, y = 390)
        rank2 = self.calRank(self.globalThreatsVectors[1] * (1+factor*0.1))
        t.label14_3 = Label(t, text = str(rank2), font = ('times', 16, 'bold'))
        if rank2 == "S" or rank2 == "A":
            t.label14_3.config(bg = 'red')
        elif rank2 == "B":
            t.label14_3.config(bg = 'orange')
        elif rank2 == "C":
            t.label14_3.config(bg = 'yellow')
        else:
            t.label14_3.config(bg = 'green')
        t.label14_3.place(x= 400, y = 390)
        t.button14_4 = Button(t, text = "Details", command = self.detailTreat2)
        t.button14_4.place(x=530, y = 390)
        ####################################################################################
        t.label15_1 = Label(t, text = "Break WLAN Auth", font = ('times', 16, 'italic'), bg = 'lightblue')
        t.label15_1.place(x= 10, y = 420)
        t.label15_2 = Label(t, text = str(self.globalThreatsVectors[2] * (1+factor*0.1)), font = ('times', 16))
        t.label15_2.place(x= 200, y = 420)
        rank3 = self.calRank(self.globalThreatsVectors[2] * (1+factor*0.1))
        t.label15_3 = Label(t, text = str(rank3), font = ('times', 16, 'bold'))
        if rank3 == "S" or rank3 == "A":
            t.label15_3.config(bg = 'red')
        elif rank3 == "B":
            t.label15_3.config(bg = 'orange')
        elif rank3 == "C":
            t.label15_3.config(bg = 'yellow')
        else:
            t.label15_3.config(bg = 'green')
        t.label15_3.place(x= 400, y = 420)
        t.button15_4 = Button(t, text = "Details", command = self.detailTreat3)
        t.button15_4.place(x=530, y = 420)
        ####################################################################################
        t.label16_1 = Label(t, text = "Hotspot Evil Twin", font = ('times', 16, 'italic'), bg = 'lightblue')
        t.label16_1.place(x= 10, y = 450)
        t.label16_2 = Label(t, text = str(self.globalThreatsVectors[3] * (1+factor*0.1)), font = ('times', 16))
        t.label16_2.place(x= 200, y = 450)
        rank4 = self.calRank(self.globalThreatsVectors[3] * (1+factor*0.1))
        t.label16_3 = Label(t, text = str(rank4), font = ('times', 16, 'bold'))
        if rank4 == "S" or rank4 == "A":
            t.label16_3.config(bg = 'red')
        elif rank4 == "B":
            t.label16_3.config(bg = 'orange')
        elif rank4 == "C":
            t.label16_3.config(bg = 'yellow')
        else:
            t.label16_3.config(bg = 'green')
        t.label16_3.place(x= 400, y = 450)
        t.button16_4 = Button(t, text = "Details", command = self.detailTreat4)
        t.button16_4.place(x=530, y = 450)
        ####################################################################################
        t.label17_1 = Label(t, text = "Cracking Password", font = ('times', 16, 'italic'), bg = 'lightblue')
        t.label17_1.place(x= 10, y = 480)
        t.label17_2 = Label(t, text = str(self.globalThreatsVectors[4] * (1+factor*0.1)), font = ('times', 16))
        t.label17_2.place(x= 200, y = 480)
        rank5 = self.calRank(self.globalThreatsVectors[4] * (1+factor*0.1))
        t.label17_3 = Label(t, text = str(rank5), font = ('times', 16, 'bold'))
        if rank5 == "S" or rank5 == "A":
            t.label17_3.config(bg = 'red')
        elif rank5 == "B":
            t.label17_3.config(bg = 'orange')
        elif rank5 == "C":
            t.label17_3.config(bg = 'yellow')
        else:
            t.label17_3.config(bg = 'green')
        t.label17_3.place(x= 400, y = 480)
        t.button17_4 = Button(t, text = "Details", command = self.detailTreat5)
        t.button17_4.place(x=530, y = 480)
        ####################################################################################
        t.label18_1 = Label(t, text = "3. Usefule Documents", font = ('times', 16, 'bold'))
        t.label18_1.place(x= 10, y = 510)
        t.button18_2 = Button(t, text = "Thread Modeling", command = self.openDocs2)
        t.button18_2.place(x=200, y = 510)
        t.button18_3 = Button(t, text = "DREAD Variant", command = self.openDocs1)
        t.button18_3.place(x=350, y = 510)
        t.button18_4 = Button(t, text = "Rating Details", command = self.openDocs3)
        t.button18_4.place(x=500, y = 510)

    def openDocs1(self):
        p = subprocess.Popen("open ../docs/DREAD.pdf", shell = True)
        
    def openDocs2(self):
        p = subprocess.Popen("open ../docs/ThreatModeling.xlsx", shell = True)

    def openDocs3(self):
        p = subprocess.Popen("open ../docs/RiskRatingDetails.pdf", shell = True)

    def detailConfig1(self):
        intro = """Auto-disconnection\n(Prefs: DisconnectionOnLogout)\n\nSome devices defaultly disable this configuration with concerns that achieves high efficiency and supports to some background applications. However, this could lead an extension of attacking vectors. Most directly it gives attackers more time and opportunity to exploit some vulnerabilities even if the user is not using the device while still staying under such Wi-Fi environment. Also, it weakens some local security tools that only gives defenses during user login.\n
         \n*Note* This parameter is independent and has effects to any kind of threat model. So when rating the risks, I simply make it as a factor multiplied to the total score calculated from other configurations.
         \n(10% increase if not enabled)"""
        tkMessageBox.showinfo("Details", intro, parent = self.child, icon = "question")
    def detailConfig2(self):
        intro = """Auto-connection\n(Prefs: JoinMode/JoinModeFallback)\n\nBy default, user devices always choose to automatically connect to available known access points when starting WiFi function or suddenly losing previous WiFi connection. \nThey will keep a history table for previous associated access points and automatically send probe request and make further authentication/association steps with available ones in that table, to keep a reliable WiFi connection.  This setting, however, can be utilized by attackers to make attacks like fake AP, Evil Twins, etc. 
        """
        tkMessageBox.showinfo("Details", intro, parent = self.child, icon = "question")
    def detailConfig3(self):
        intro = """Remote Access\n(SSH Enabled/Disabled)\n\nThis stands for the security mechanism used by user`s local devices, generally as root user-password based authentication/authorization. Sometimes, it may be unavoidable that attacker may take advantage of the Wi-Fi pure insecure nature to break the WLAN authentication or other layer-2 related security, however to prevent the devices from terrible damage, local security is the last safeguard preventing attackers from breach into local system and get root privilege to take overall control of the system. Here, I mainly focused on whether the local machine enables the SSH remote login function.(System password is hard to be analyzed via the program)
        """
        tkMessageBox.showinfo("Details", intro, parent = self.child, icon = "question")
    def detailConfig4(self):
        intro = """SSID property\n\nGenerally there are three situation for user`s customized SSID.\n\nDefault SSID: Default SSID usually expose extra information about Wi-Fi access points` producer and model, or even version of firmware, which will ease attacker`s attempts to find some known vulnerabilities related to certain access points.
        \nPublic normal SSID: This is the general situation that the administrator changes the default SSID into some other names, this can be better than the former one, however essentially they are similar since device`s mac address always contains information about the devices. Another situation could be the admin named access point with a meaningful content, which actually expose some private information like location, owner`s personal information, etc, leading to potential risks like social engineering attacks.
        \nHidden SSID: This is not normal for public wireless access points since it contradicts with the purpose that offering user`s convenience when using the wireless network. However it can be a method to trivially reduce the attack vectors, since it increase the workload for attackers to discover and link the hidden access point with its other physical information.
        """
        tkMessageBox.showinfo("Details", intro, parent = self.child, icon = "question")
    def detailConfig5(self):
        intro = """Authentication/Encryption\n\nFinally, the biggest part for evaluation is still about encryption and authentication. Some authentication protocols like EAP only associates with enterprise-level devices which is not very practical to discuss for public Wi-Fi. So basically I only categorized it here as:
        \nOpen/Open+RADIUS/WEP/WPA/WPA+WPA2/WPA2\nin which Open+RADIUS is not easy to be detected, however for most threat models it has trivial difference with Open ones since RADIUS only improve the security at higher layers.
        """
        tkMessageBox.showinfo("Details", intro, parent = self.child, icon = "question") 

    def detailTreat1(self):
        intro = """Sniffing\n\nSoftware sniffers allow eavesdroppers to passively intercept data sent between your web browser and web servers on the Internet. This is the easiest and most basic kind of attack. Any email, web search or file you transfer between computers or open from network locations on an unsecured network can be captured by hackers.  
        Sniffing software is readily available for free on the web and there are 184 videos on YouTube to show budding hackers how to use them. 
        The only way to protect yourself against WiFi sniffing in most public WiFi hotspots is to use a VPN, such as PRIVATE WiFi\n
        Generally, sniffing can be performed only using passive sniffer(wireshark, airodump-ng)
        - The direct damage from sniffing is trivial, especially for AP using WEP/WPA/WPA2. Open AP may leak some sensitive info or credentials from users.
        - Sniffing is very easy to perform. Hidden ssid will make it a little inconvenient, but very trivial effects.
        - Sniffing can contribute to some further attacks, WEP/WPA cracking, other attacks that However sniffing is almost the very first step of all other complex attacks, it's necessary but not that decisive. 
        - If SSID is hidden, attacker needs to firstly discover hidden ssid, then sniffing can be targeted to the clients. This is the reason that hidden SSID relatively decreases the risk. Methods from attacker to handle with Hidden SSID:
        1. Passively monitor clients connecting to AP.
        2. De-auth clients and monitor reconnection.
        """
        tkMessageBox.showinfo("Details", intro, parent = self.child, icon = "question") 

    def detailTreat2(self):
        intro = """Fake Access Point\n\n(Rogue Networks): `Free Public WiFi` networks are ad-hoc networks advertising `free` Internet connectivity. Once you connect to a viral network, all of your shared folders are accessible to every other laptop connected to the networks. A hacker can then easily access confidential data on your hard drive. These viral networks can be used as bait by an Evil Twin. `Free Public WiFi` networks turn up in many airports. Don`t connect to these networks and you won`t infect your laptop. If you find this kind of network on your laptop, delete it and reconfigure your adapter to avoid auto-connecting to any wireless network.
        When talking about fake access point as a threat, it only means that attacker creates a fake access point in the wave range and wait clients to connect to it without further achievements.
        - It has little relations with AP`s configuration. User`s setting that whether their devices connect APs automatically will somehow affect the ease for attackers.
        - Fake AP itself can lead to little damage. It can affect all users in the range. It can used to perform Evil Twin, which is a severe threat.
        - Creating a fake AP is essentially easy but needs some knowledges and experiences of certain tools, like airbase-ng. 
        - A device that turn down the auto-connect configuration will make attacker harder to lure user to connect. It's exposed there, but only if the user himself/herself want to connect to it, does this threat succeed.
        """
        tkMessageBox.showinfo("Details", intro, parent = self.child, icon = "question") 

    def detailTreat3(self):
        intro = """Break WLAN Authentication\n\n
        - For open AP, authentication only has two packets, attacker can easily craft a fake auth packet to crack it. Open-Radius makes no big difference with open at this layer, attacker can easily associate with the AP, Radius only works in further network layer access control.
        - For shared key auth, more complex request/responses verification occurs during the authentication.
        1. client -Auth request -> AP
        2.AP -128 byte plaintext(challenge) -> client
        3. client encrypts the challenge with IV, RC4 stream cipher, shared key, - encrypted challenge -> AP
        4. AP verify the encrypted challenge, confirm/deny access - >client
        Attacker need to firstly sniff enough packets and extract/compute the key stream using airodump-ng. Then use aireplay-ng to send fake auth packets based on key stream obtained. Also, WPA/WPA2 make it much harder to crack than WEP 
        - Breaking WLAN Authentication leads to unauthorized user connect to AP. Which is actually fine in the context of public hotspots, since shared-key of public AP can always be easily propagated by users. However, a weak authentication will more likely attract attackers and give them convenience to do further harm. Directly, this threat doesn't affect normal users and has little damage.
        - It can lead to further Damage: Attacker can try to (take control of) get access to AP settings. If SSID exposes the producer even type of AP obviously, it make attacker easier to find some general known vulnerabilities, ip address, default account/password, etc. However, the possibility of success cracking AP configuration and the damage it will lead to is limited.
        """ 
        tkMessageBox.showinfo("Details", intro, parent = self.child, icon = "question") 

    def detailTreat4(self):
        intro = """Hotspots Evil Twin\n\nThis is a rogue WiFi access point that appears to be a legitimate one, but actually has been set up by a hacker to eavesdrop on wireless communications. An evil twin is the wireless version of the `phishing` scam: an attacker fools wireless users into connecting a laptop or mobile phone to a tainted hotspot by posing as a legitimate provider. When a victim connects, the hacker can launch man-in-the-middle attacks, listening in on all Internet traffic, or just ask for credit card information in the standard pay-for-access deal. 
        - It leads to damage like: User can be communicated by attacker via network layer, ping(DoS), ssh(remote access), wifi phishing, etc. The likelihood depends on user's local security settings(root password, ssh)
        - It can also be used to contribute to MITM attack by relaying it to AP or directly to Internet.
        - It is always targeted at certain client due to the step of de-authentication, but can be extended to affect more(de-authenticate all connect users).
        - This attack is a little complicate, not the one novel attacker can easily achieve. But with help of some tools, airodump-ng, aireplay-ng..., it can be learnt quickly. It is easy to perform it with Open AP, but since attacker need to make the user thinking connected with the right one. There should be little difference between fake one and original one superficially, which also includes the authentication/encryption methods. A successful evil twin should let the user connect to it automatically, not simply a fake AP, so if original AP uses WEP/WPA/WPA-WPA2/WPA2, user's device will use the share-key to request connection. Attacker need to firstly crack the key, then craft a fake one with that key. Or accept any encrypted challenge from clients to confirm the successful authentication. Both ways need complex steps and time consuming. WPA/WPA2 are harder than WEP.
        """
        tkMessageBox.showinfo("Details", intro, parent = self.child, icon = "question") 

    def detailTreat5(self):
        intro = """Cracking Password\n\nThis is easy to evaluation due to the different encryption algorithm and complexity
        """
        tkMessageBox.showinfo("Details", intro, parent = self.child, icon = "question")        

    def mitigationSuggestion(self):
        if self.globalThreatsVectors == [0,0,0,0,0]:
            tkMessageBox.showinfo("Warning", "You should check this after evaluating a target Wi-Fi access point", parent = self, icon = "question") 
            return
        t = Toplevel(self)
        t.wm_title("Security Suggestions")
        ws = t.winfo_screenwidth()
        hs = t.winfo_screenheight()
        w = 600
        h = 600
        x = (ws/2) - (w/2)
        y = (hs/2) - (h/2)
        t.geometry('%dx%d+%d+%d' % (w, h, x, y))
        t.attributes("-topmost", True)
        caption1 = "Highly Recommended Approaches to Secure your Wireless Web Surfing\n\n"
        caption1 = caption1 + "###According to your local configurations###"
        t.label_caption1 = Label(t, text = caption1, font = ('black', 16))
        t.label_caption1.pack(side = 'top')
        local_config = ""
        if self.globalScanning[0] != 1:
            local_config = local_config + "*Enable DisconnectOnLogout*\n(Use Command: sudo airport prefs disconnectonlogout=yes)"
        if self.globalScanning[1] != 0:
            local_config = local_config + "\n*Turn off Auto-connection*\n(Use Command: sudo airport prefs joinmode=unknown)\n(Use Command: sudo airport prefs joinmodefallback=donothing)"
        if self.globalScanning[2] != 0:
            local_config = local_config + "\n*Disable SSH Remote Access*\n(Go to System Preference -> Sharing -> Unselect Remote Login)"
        t.label_local = Label(t, text = local_config, font = ('times', 14))
        t.label_local.pack(side = 'top')
        
        caption2 = "\n###According to Target Access Point`s Configurations###"
        t.label_caption2 = Label(t, text = caption2, font = ('black', 16))
        t.label_caption2.pack(side = 'top')
        ap_config = ""
        if self.globalScanning[3] == 2:
            ap_config = ap_config + "(Security Warnings are provided here, make you be aware of\n potential risks if connected to the target network)\n*Target`s SSID*\n(Warning: This Access Point uses a SSID that easily exposes\n information of devices to potential attackers.)"
        if self.globalScanning[4] < 3:
            ap_config = ap_config + "\n#Target`s Authentication/Encryption*\n(Their device doesn't use most secure authentication methods,\n which may make it easier for attacker to break.)" 
        t.label_ap = Label(t, text = ap_config, font = ('times', 14))
        t.label_ap.pack(side = 'top')

        caption3 = "\n###General Methods to Make Your Wireless Connection More Secure###"
        t.label_caption3 = Label(t, text = caption3, font = ('black', 16))
        t.label_caption3.pack(side = 'top')
        general_suggestion = "1. Choose your network wisely\n2. Use a Virtual Private Network when connecting\n3. Turn off all file sharing setting\n4. Check for HTTPS when browsering webpages\n5. Patch your applications frequently\n6. Enable two-factor authentication\n7. Enable your firewall\n8. Turn Wi-Fi off when not using it.\n9. Forget the network"
        t.label_general = Label(t, text = general_suggestion, font = ('times', 14))
        t.label_general.pack(side = 'top')
        general_suggestion2 = "10. OF COURSE, USE WI-FI SCOUT!!!"
        t.label_general2 = Label(t, text = general_suggestion2, font = ('black', 18))
        t.label_general2.pack(side = 'top')

    def calRank(self, score):
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

    def checkRoot(self, scanning):
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

    def checkHidden(self, target): #not shown, run at background
        p = subprocess.Popen(AIRPORT_PATH + " -s", stdout = subprocess.PIPE, shell = True)
        out, err = p.communicate()
        p2 = subprocess.Popen(AIRPORT_PATH + " -s", stdout = subprocess.PIPE, shell = True)
        out2, err2 = p2.communicate()
        if target in out or target in out2:
            return False
        else:
            return True

    def checkSSIDVendor(self, ssid):
        f = open('ssid.csv')
        ssid_f = csv.reader(f)
        for row in ssid_f:
            if row[0] in ssid:
                return True
        return False

    def loadMappingThreatsScore(self, configure_to_threat):
        f = open('ThreatsData.csv')
        csv_f = csv.reader(f)
        for row in csv_f:
            scanning = map(int, row[1:5])   #exclude DisconnectOnLogout
            threats = map(float, row[5:10])
            key = str(row[1])+str(row[2])+str(row[3])+str(row[4])  
            #print key
            configure_to_threat[key] = threats

    def __init__(self, master=None):
        Frame.__init__(self, master)
        self.child = None
        self.target = "default for test"                #selected ssid
        self.configure_to_threat = {}   #map:configuration -> threat scores
        #self.configure_to_DREAD = {}    #map:configuration -> DREAD details(for 5 threats)
        self.globalScanning = [0,2,1,2,0]     #scaned configurations
        self.globalThreatsVectors = [0, 0, 0, 0, 0]
        self.cache_scan_all = {}        #stored wifi info for every ssid from scanAll
        self.loadMappingThreatsScore(self.configure_to_threat)  #load map:configuration -> threat scores
        self.pack()
        self.createWidgets()

def CreateMainWindow(root):
    root.title("WiFi Scout")
    ws = root.winfo_screenwidth()
    hs = root.winfo_screenheight()
    w = 550
    h = 550
    x = (ws/2) - (w/2)
    y = (hs/2) - (h/2)
    root.geometry('%dx%d+%d+%d' % (w, h, x, y))
    root.attributes("-topmost", True)
    #root.config(bg = 'lightblue')
    app = Application(master=root)
    app.mainloop()

def Main():
    root = Tk()
    CreateMainWindow(root)

if __name__ == '__main__':
    Main()