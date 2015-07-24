from Tkinter import *
from ttk import *
from os import environ as env
from os import pipe

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import inet
from ryu.ofproto import ether
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import dhcp
from ryu.lib.packet import udp
from ryu.lib.packet import arp
from ryu.controller.dpset import DPSet
from ryu.lib.packet import icmp
from ryu.lib import hub


quote = """HAMLET: To be, or not to be--that is the question:
            Whether 'tis nobler in the mind to suffer
            The slings and arrows of outrageous fortune
            Or to take arms against a sea of troubles
            And by opposing end them. To die, to sleep--
            No more--and by a sleep to say we end
            The heartache, and the thousand natural shocks
            That flesh is heir to. 'Tis a consummation
            Devoutly to be wished."""

class App:

    def __init__(self, master, connection=None):
	#self.connection = connection
        self.master = master
        self.content = Frame(master)
        self.content.grid()
        
        self.routing = IntVar()
        self.blacklist = IntVar()
        self.throttle = IntVar()
        self.ping = IntVar()
        self.sandbox = IntVar()

        Label(self.content, text="Toolbox", style="App.TLabel").grid()
        self.cRouting = Checkbutton(self.content, text="Routing",\
                                    variable=self.routing)
        self.cBlacklist = Checkbutton(self.content, text="Blacklist",\
                                    variable=self.blacklist)
        self.cThrottle = Checkbutton(self.content, text="Throttle",\
                                    variable=self.throttle)
        self.cPing = Checkbutton(self.content, text="Ping",\
                                    variable=self.ping)
        self.cSandbox = Checkbutton(self.content, text="Sandbox",\
                                    variable=self.sandbox)
        self.run = Button(self.content, text="Run", command= lambda: self.transform(self.routing.get(), \
                                        self.blacklist.get(), self.ping.get(), self.throttle.get(),\
                                         self.sandbox.get())) 
    
        self.logo = PhotoImage(master=self.content, file='ccwlogo.gif')
        Label(self.content, image=self.logo).grid(row=1, column=1, rowspan=6)
        self.cRouting.grid(row=1, sticky="w")
        self.cThrottle.grid(row=2, sticky="w")
        self.cPing.grid(row=3, sticky="w")
        self.cBlacklist.grid(row=4, sticky="w")
        self.cSandbox.grid(row=5, sticky="w")
        self.run.grid(row=6)

	
    def transform(self, routing, blacklist, ping, throttle, sandbox):
        frame = Frame(self.master, height=500, width=500, style="App.TFrame")
        self.content.destroy()
        frame.grid()
        col = 0
        if throttle:
            self.create_throttle(frame, col)
            col += 1
        if blacklist:
            self.create_blacklist(frame, col)
            col += 1
	if routing:
            self.create_routing(frame, col)
            col += 1
	if ping:
	    self.create_ping(frame, col)
            col += 1
	if sandbox:
	    self.create_sandbox(frame, col)
            col += 1
	
    def create_routing(self, parent, col):
	frame = Frame(parent)
        label = Label(frame, text="   Routing App Under Construction :(   ", style="App.TLabel")
	frame.grid(column=col, row=0)
        label.grid()
    def create_sandbox(self, parent, col):
        frame = Frame(parent)
        label = Label(frame, text="   SandBox under construction :(   ", style="App.TLabel")
        frame.grid(column=col, row=0)
        label.grid()

    def ping_this(self, ip):
	pass

    def create_ping(self, parent, col):
	frame = Frame(parent)
        label = Label(frame, text="Ping Tool", style="App.TLabel")
        directions = Label(frame, text="Enter an IP Address")
        ping = Button(frame, text="Ping", \
            command=lambda:self.ping_this(self.ping_entry.get()))

        self.ping_entry = Entry(frame)

        frame.grid(column=col, row=0, sticky=NS)
        label.grid()
        directions.grid(column=0, row=2, columnspan=2, pady=5)
        self.ping_entry.grid(column=0, row=3, columnspan=2)
        ping.grid(column=0, row=4, pady=5)

    def create_blacklist(self, parent, col):
        """
        Creates an interface for manipulating the blacklist app
        @Todo: link to controller
        """
        frame = Frame(parent)
        label = Label(frame, text="Blacklist Tool", style="App.TLabel")
        label_frame = LabelFrame(frame, text="Blacklisted IPs")
        directions = Label(frame, text="Enter an IP Address")
        add = Button(frame, text="Add", \
            command=lambda:self.add_to_blacklist(self.blacklist_entry.get()))
        remove = Button(frame, text="Remove",\
            command=lambda:self.remove_from_blacklist(self.blacklist_entry.get()))

        self.blacklisted = []
        self.blacklist = Listbox(label_frame)
        self.blacklist_entry = Entry(frame)
        
        frame.grid(column=col, row=0)
        label.grid()
        label_frame.grid(column=0, row=1, columnspan=2)
        self.blacklist.grid(column=0, row=1, columnspan=2)
        directions.grid(column=0, row=2, columnspan=2, pady=5)
        self.blacklist_entry.grid(column=0, row=3, columnspan=2)
        add.grid(column=0, row=4, pady=5)
        remove.grid(column=1, row=4, pady=5)
        
    def add_to_blacklist(self, ip):
        #duplicate
	print "Calling add_to_blacklist..."
        if ip in self.blacklisted:
            return

        print(ip)
        self.blacklisted.append(ip)
        b = ""
        for ip in self.blacklisted:
            b += ip+ " "
        env['blacklisted'] = b
        self.blacklist.insert(END, ip)
	print "added "+ip+" to list.\n"
	print "Env List:"
	print env['blacklisted']
	print "\nLocal List:"+str(b)

    def remove_from_blacklist(self, ip):
	print "Calling remove_from_blacklist...\n"
        en_blk_list = env['blacklisted']
	blk_list = en_blk_list.split()
	#try:
	index = blk_list.index(ip)
	del blk_list[index]
	print "Deleting "+str(ip)+"\n"
	b = ""
        print "Is "+str(ip)+" in "+str(blk_list)+"?\n"
	for ip in blk_list:
		print "yep!\n"
       		b += ip+ " "
        	env['blacklisted'] = b	
		index = blk_list.index(ip)
		print "Ip found in blk_list:"+str(index)
		blk_list.delete(index)
	#except:
	#	pass

    def remove_from_throttlelist(self, ip):
        pass

    def add_to_throttlelist(self, ip):
        #duplicate check

        if ip in self.throttled:
            return
	
        self.throttled.append(ip)
	self.connection.send(self.throttled)
        self.throttlelist.insert(END, ip)
	
	
    def create_throttle(self, parent, col):
        frame = Frame(parent)
        label = Label(frame, text="Throttle Tool", style="App.TLabel")
        label_frame = LabelFrame(frame, text="Throttled Ips")
        directions = Label(frame, text="Enter Ip address")
        add = Button(frame, text="Add", \
            command=lambda:self.add_to_throttlelist (self.throttle_entry.get()))
        remove = Button(frame, text="Remove",\
            command=lambda:self.remove_from_throttlelist(self.throttle_entry.get()))

        self.throttled = []
        self.throttlelist = Listbox(label_frame)
        self.throttle_entry = Entry(frame)

        frame.grid(column=col, row=0)
        label.grid()
        label_frame.grid(column=0, row=1, columnspan=2)
        self.throttlelist.grid(column=0, row=1, columnspan=2)
        directions.grid(column=0, row=2, columnspan=2, pady=5)
        self.throttle_entry.grid(column=0, row=3, columnspan=2)
        add.grid(column=0, row=4, pady=5)
        remove.grid(column=1, row=4, pady=5)
        
class SimpleMonitor(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

	_CONTEXTS = {
			'dpset': DPSet,
		}
	
	def __init__(self, *args, **kwargs):
	    super(SimpleMonitor, self).__init__(*args, **kwargs)
	    self.threads.append(hub.spawn(self._gui))

    	def _gui(self):
	    root = Tk()
            root.title("SDN App")
    	    s = Style()
    	    s.theme_use("clam")
    	    s.configure('App.TLabel', font="Times 12 bold")
    	    s.configure('App.TFrame', background='cyan')
    	    app = App(root)
	    root.mainloop()
    
		
		

if __name__ == "__main__":
    root = Tk()
    root.title("SDN App")
    s = Style()
    s.theme_use("clam")
    s.configure('App.TLabel', font="Times 12 bold")
    s.configure('App.TFrame', background='cyan')
    app = App(root)
    
    #import IPython
    #IPython.embed()
    root.mainloop()

