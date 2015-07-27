from gi.repository import Gtk
from gi.repository import Pango
#from Switch_DHCP_8JUN import SimpleSwitch
import subprocess
from os import environ as env
                   
class MyApp (object):

    def __init__(self, connection):
	self.connection = connection
        self.builder = Gtk.Builder()
        self.builder.add_from_file("gui.glade")
        self.builder.connect_signals(self)
        self.builder.get_object("windowmain").show_all()
        self.rtg = False
        self.fp = False
        self.sb = False
	self.ping = False
	self.ftp = False


    def on_runButton_clicked(self, buttonbox):
        print self.rtg
        print self.fp
        print self.sb
	print self.ping
	print self.ftp
        if self.rtg:
            print "Routing"
            self.builder.get_object("windowrb").show_all()
        if self.fp:
	        print "Fingerprint"
	        self.builder.get_object("windowfp").show_all()
        if self.sb:
            print "Sandbox"
            self.builder.get_object("windowsb").show_all()
	if self.ping:
	    print "Ping App"
	    self.builder.get_object("windowPing").show_all()
	if self.ftp:
	    print "FTP Corrupt"
	    self.builder.get_object("windowFTP").show_all()
        
    def on_checkbuttonRtg_toggled(self, button):
        checkbuttonRtg = Gtk.CheckButton("Routing")
        checkbuttonRtg.connect("toggled", self.on_checkbuttonRtg_toggled, "1")
        
        if button.get_active():
           self.rtg = True
           print self.rtg
        else:
           self.rtg = False
           
    def on_checkbuttonFp_toggled(self, button):
        if button.get_active():
            self.fp = True
            print("Activate Fingerprint")     
        else:
	    self.fp = False
			   
    def on_checkbuttonSb_toggled(self, button):
        if button.get_active():
            self.sb = True
            print("Activate Sandbox")
        else:
	    self.sb = False   

    def on_checkbuttonPing_toggled(self, button):
        if button.get_active():
            self.ping = True
            print("Activate Ping")
        else:
	    self.ping = False  
            
    def on_checkbuttonFTP_toggled(self, button):
        if button.get_active():
            self.ftp = True
            print("Activate FTP Corruption")
        else:
	    self.ftp = False  
            

    def enter_callback(self, widget, entry):
	entry_text = entry.get_text()
	print "Entry contentsL %s\n" % entry_text
            
        
    def refreshIPs(self, whichfile, whichview):
        blIP = self.builder.get_object(whichview)
        bltextbuffer = blIP.get_buffer()
        files = open(whichfile)
        data = files.readlines()
        if data:
            data.pop(0)
            data.sort()
            data = ''.join(data)
            print data
            bltextbuffer.set_text(data)
        files.close()

    def refreshIPs_from_string(self, strData, whichview):
        blIP = self.builder.get_object(whichview)
        bltextbuffer = blIP.get_buffer()
        print strData
        bltextbuffer.set_text(strData)
		
#################
###  SandBox  ###
#################            
    def on_viewButton_clicked(self, buttonbox):          
        self.refreshIPs("DNS_Blacklist", "textview1")
        
    def on_addButton_clicked(self, buttonbox):
		written = self.builder.get_object("entry1")
		newtext = written.get_text()
		files = open("DNS_Blacklist", "a")
		data = files
		data.write(newtext + "\n")    
		data.close()
		self.refreshIPs("DNS_Blacklist", "textview1")
		
    def on_removeButton_clicked(self, buttonbox):
        written = self.builder.get_object("entry1")
        rmtext = written.get_text()
        files = open("DNS_Blacklist", "r")
        data = files.readlines()
        files.close()
        files = open("DNS_Blacklist", "w")
        for line in data:
            if line != rmtext + "\n":
				files.write(line)
        files.close()
        self.refreshIPs("DNS_Blacklist", "textview1")
    
    def on_sbToggle_toggled(self, button):
        sbToggle = self.builder.get_object("sbToggle")
        if sbToggle.get_active():
            print "Running Sandbox"           
        else:
			print "Stopping Sandbox"           
#################
### BLACKHOLE ###
#################			
    def on_viewButton1_clicked(self, buttonbox):          
        self.refreshIPs("blackhole.txt", "textview2")   
        
    def on_addButton1_clicked(self, buttonbox):
		written = self.builder.get_object("entry2")
		newtext = written.get_text()
		files = open("blackhole.txt", "a")
		data = files
		data.write(newtext + "\n")    
		data.close()
		self.refreshIPs("blackhole.txt", "textview2")
		
    def on_removeButton1_clicked(self, buttonbox):
        written = self.builder.get_object("entry2")
        rmtext = written.get_text()
        files = open("blackhole.txt", "r")
        data = files.readlines()
        files.close()
        files = open("blackhole.txt", "w")
        for line in data:
            if line != rmtext + "\n":
				files.write(line)
        files.close()
        self.refreshIPs("blackhole.txt", "textview2")
    
    def on_blToggle_toggled(self, button):
        blToggle = self.builder.get_object("blToggle")
        if blToggle.get_active():
            print "Running Blackhole"          
        else:
			print "Stopping Blackhole"	
#################
###  THROTTLE ###
#################
    def on_viewButton2_clicked(self, buttonbox):          
        self.refreshIPs("throttle.txt", "textview3")   
        
    def on_addButton2_clicked(self, buttonbox):
		written = self.builder.get_object("entry3")
		newtext = written.get_text()
		files = open("throttle.txt", "a")
		data = files
		data.write(newtext + "\n")    
		data.close()
		self.refreshIPs("throttle.txt", "textview3")
		
    def on_removeButton2_clicked(self, buttonbox):
        written = self.builder.get_object("entry3")
        rmtext = written.get_text()
        files = open("throttle.txt", "r")
        data = files.readlines()
        files.close()
        files = open("throttle.txt", "w")
        for line in data:
            if line != rmtext + "\n":
				files.write(line)
        files.close()
        self.refreshIPs("throttle.txt", "textview3")
    
    def on_thToggle_toggled(self, button):
        thToggle = self.builder.get_object("thToggle")
        if thToggle.get_active():
            print "Running Throttle"          
        else:
	        print "Stopping Throttle"        
    def on_windowmain_destroy(self, widget, data = None):
        Gtk.main_quit()


#################
###  Ping App ###
#################
    def on_Submit_IP_Button_clicked(self, buttonbox):
	IPaddr = self.builder.get_object("IP_Entry").get_text()
	if IPaddr != "": 
        	f= open("ping.txt", "w")
		f.write(IPaddr)
		f.close()			       
	else:
		f= open("ping_result.txt", "r")
		f_str=f.read()
		self.refreshIPs_from_string(f_str, "view_ping_result")
		f.close()

#################
###  FTP App  ###
#################
    def on_refreshFtp_clicked(self, buttonbox):
	    f= f.open("ftp_log.txt", 'r')
	    f_str= f.read()
	    self.refreshIPs_from_string(f_str, "ftpInfo")

#################
# Finger Print  #
#################
    def on_refreshButton_clicked(self, buttonbox):
	    f= f.open("fingerprint_log.txt", "r")
	    f_str= f.read()
	    self.refreshIPs_from_string(f_str, "fingerprint_display")
	    f.close()

    def on_clearButton_clicked(self, buttonbox):
	    f= f.open("fingerprint_log.txt", "w")
	    f_str= f.write('')
	    self.refreshIPs_from_string(f_str, "fingerprint_display")
	    f.close()
	
if __name__ == "__main__":
    main = MyApp()
    Gtk.main()
