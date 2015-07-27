import logging
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls, DEAD_DISPATCHER
from ryu.lib import hub
import numpy as np
import matplotlib.pyplot as plt
import time
from Link import Link, LinkState
from Switch import Switch
from LLDPPacket import LLDPPacket
from Port import Port, PortState, PortData, PortDataState
from numpy import matlib
from datetime import datetime
from operator import attrgetter
import Routing
from ryu.ofproto import ofproto_v1_0
from ryu.lib.packet import packet, ethernet, lldp
from ryu.lib import addrconv, hub
from ryu.lib.mac import DONTCARE_STR
from ryu.ofproto.ether import ETH_TYPE_LLDP
from ryu.topology import event
from ryu.ofproto import nx_match

from networkx.algorithms.approximation.vertex_cover import min_weighted_vertex_cover
from multiprocessing import Process, Pipe
import time
from gui import App
from Tkinter import *
from ttk import *
from os import environ as env
import networkx as nx
from GenerateTopology import generate
import pexpect
from npssdn import MyApp
from gi.repository import Gtk
from gi.repository import Pango

#assuming python is really fast the computation time is neglgible?
class SimpleMonitor(Routing.SimpleSwitch):

    LLDP_SEND_GUARD = .05
    LLDP_SEND_PERIOD_PER_PORT = .9
    TIMEOUT_CHECK_PERIOD = 5.
    LINK_TIMEOUT = TIMEOUT_CHECK_PERIOD * 2
    LINK_LLDP_DROP = 5
    LLDP_PACKET_LEN = len(LLDPPacket.lldp_packet(0, 0, DONTCARE_STR, 0))
    DEFAULT_TTL = 120

    
    def __init__(self, *args, **kwargs):
        super(SimpleMonitor, self).__init__(*args, **kwargs)
        self.is_active = True
        
	#Topology Discovery
	self.link_discovery = True
        self.port_state = {}          # datapath_id => ports
        self.ports = PortDataState()  # Port class -> PortData class
        self.links = LinkState()      # Link class -> timestamp
        self.link_length = 0
	

	self.mac_to_port = {}
        self.ip_to_port = {}
        self.dpid_to_port = {}
	self.dpid_to_ip = {}
        self.dps = {}
        self.dpid_to_node = {0x00012c59e5107640:1, 0x0001c4346b94a200:2,\
                                         0x0001c4346b99dc00:4, 0x0001c4346b946200:5,\
                                         0x0001c4346b971ec0:6, 0x0001f0921c219d40:13}

        #SDN Application data structures
	self.blacklist = []
	self.throttle_list = []

	#threads
	self.analyzer = Analyzer()
        self.lldp_event = hub.Event()
	self.link_event = hub.Event()
        self.threads.append(hub.spawn(self.lldp_loop))
	self.threads.append(hub.spawn(self.link_loop))
	#self.parent_conn, child_con = Pipe()
	#self.gui_thread = Process(target=self._gui, args=(child_con,))
	#self.gui_thread.start()
        #self.threads.append(hub.spawn(self._monitor))

	self.throttle_list = []
        with open('V','w') as f:
            f.flush()
        with open('D','w') as f:
            f.flush()
        with open('L','w') as f:
            f.flush()	

    def _gui(self, connection):
	#root = Tk()
        #root.title("SDN App")
        #s = Style()
        #s.theme_use("clam")
        #s.configure('App.TLabel', font="Times 12 bold")
        #s.configure('App.TFrame', background='cyan')
	#on_button = Button(root, text="Turn ports on", command=lambda: turn_all_ports_on(self.dps,\
	#		self.dpid_to_ip))

	#on_button.pack()

	
        #app = App(root, connection)
	#root.mainloop()
	main = MyApp(connection)
	Gtk.main()

    def _monitor(self):
        while True:
	 #   try:
	 #   	print(self.parent_conn.recv())
	 #   except:
	 #	hub.sleep(2)
            for dp in self.dps:
                if dp in self.dpid_to_node:
                    self._request_port_stats(self.dps[dp])
            hub.sleep(2)
    
    def draw_graph(self, timeout, draw=False):
        G = nx.Graph()
        
        plt.clf()
        labels = {}
        nodes = []
        for id in self.dps:
            G.add_node(hex(id))
            labels[hex(id)] = hex(id)
            nodes.append(hex(id))
    
        for link in self.links:
            G.add_edge(hex(link.src.dpid), hex(link.dst.dpid))
        pos = nx.spring_layout(G)
        
        vertex_cover = min_weighted_vertex_cover(G)
        for node in nodes:
            G.remove_node(node)
            
        for node in vertex_cover:
            nodes.remove(node)

	if draw:
            nx.draw(G)
            nx.draw_networkx_nodes(G, pos, nodelist=nodes, node_color='g',\
                                node_size=500, alpha=0.8)
                                
            nx.draw_networkx_nodes(G, pos, nodelist=vertex_cover, node_color='b',\
                                node_size=1000, alpha=0.8)
        
        for link in self.links:
            G.add_edge(hex(link.src.dpid), hex(link.dst.dpid))
        if draw:
	    nx.draw_networkx_edges(G, pos)
        
        #nx.draw_networkx_labels(G, pos, labels, font_size=16)
        
#	plt.savefig('topology.png')
	#plt.show()
            plt.pause(timeout)
        #generate(self.dps, self.links)
		
    def _request_port_stats(self, datapath):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_NONE)
		datapath.send_msg(req)

		
    def close(self):
        self.is_active = False
        if self.link_discovery:
            self.lldp_event.set()
	    self.link_event.set()
	    hub.joinall(self.threads)
            
    def _register(self, dp):
        assert dp.id is not None

        self.dps[dp.id] = dp
        if dp.id not in self.port_state:
            self.port_state[dp.id] = PortState()
            for port in dp.ports.values():
                self.port_state[dp.id].add(port.port_no, port)

    def _unregister(self, dp):
        if dp.id in self.dps:
            del self.dps[dp.id]
            del self.port_state[dp.id]

    def _get_switch(self, dpid):
        if dpid in self.dps:
            switch = Switch(self.dps[dpid])
            for ofpport in self.port_state[dpid].values():
                switch.add_port(ofpport)
            return switch

    def _get_port(self, dpid, port_no):
        switch = self._get_switch(dpid)
        if switch:
            for p in switch.ports:
                if p.port_no == port_no:
                    return p

    def _port_added(self, port):
        lldp_data = LLDPPacket.lldp_packet(
            port.dpid, port.port_no, port.hw_addr, self.DEFAULT_TTL)
        self.ports.add_port(port, lldp_data)
        # LOG.debug('_port_added dpid=%s, port_no=%s, live=%s',
        #           port.dpid, port.port_no, port.is_live())

    def _link_down(self, port):
        try:
            dst, rev_link_dst = self.links.port_deleted(port)
        except KeyError:
            # LOG.debug('key error. src=%s, dst=%s',
            #           port, self.links.get_peer(port))
            return
        link = Link(port, dst)
        self.send_event_to_observers(event.EventLinkDelete(link))
        if rev_link_dst:
            rev_link = Link(dst, rev_link_dst)
            self.send_event_to_observers(event.EventLinkDelete(rev_link))
        self.ports.move_front(dst)

	

    @set_ev_cls(ofp_event.EventOFPStateChange,
            [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            
            dp_multiple_conns = False
            if datapath.id in self.dps:
                dp_multiple_conns = True
            
            self.logger.debug('register datapath: %016x', datapath.id)
            print("New DPID: " + `datapath.id`)
            self._register(datapath)
            switch = self._get_switch(datapath.id)
            if not dp_multiple_conns:
                self.send_event_to_observers(event.EventSwitchEnter(switch))
                
            ofproto = datapath.ofproto
            ofproto_parser = datapath.ofproto_parser        
            if ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
                rule = nx_match.ClsRule()
                rule.set_dl_dst(addrconv.mac.text_to_bin(
                                lldp.LLDP_MAC_NEAREST_BRIDGE))
                rule.set_dl_type(ETH_TYPE_LLDP)
                actions = [ofproto_parser.OFPActionOutput(
                    ofproto.OFPP_CONTROLLER, self.LLDP_PACKET_LEN)]
                datapath.send_flow_mod(
                    rule=rule, cookie=0, command=ofproto.OFPFC_ADD,
                    idle_timeout=0, hard_timeout=0, actions=actions,
                    priority=0xFFFF)
                    
            if not dp_multiple_conns:
                for port in switch.ports:
                    if not port.is_reserved():
                        self._port_added(port)
                        
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.dps:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                self._unregister(datapath)
                self.send_event_to_observers(event.EventSwitchLeave(switch))
            
            for port in switch.ports:
                if not port.is_reserved():
                    self.ports.del_port(port)
                    self._link_down(port)
                    
        #self.draw_graph(.2)
        self.lldp_event.set()


    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        msg = ev.msg
	reason = msg.reason
	dp = msg.datapath
	ofpport = msg.desc
	if reason == dp.ofproto.OFPPR_ADD:
		# LOG.debug('A port was added.' +
		# '(datapath id = %s, port number = %s)',
		# dp.id, ofpport.port_no)
		self.port_state[dp.id].add(ofpport.port_no, ofpport)
		self.send_event_to_observers(\
			event.EventPortAdd(Port(dp.id, dp.ofproto, ofpport)))

		if not self.link_discovery:
			return

		port = self._get_port(dp.id, ofpport.port_no)
		if port and not port.is_reserved():
			self._port_added(port)
			self.lldp_event.set()
	elif reason == dp.ofproto.OFPPR_DELETE:
		# LOG.debug('A port was deleted.' +
		# '(datapath id = %s, port number = %s)',
		# dp.id, ofpport.port_no)
		self.port_state[dp.id].remove(ofpport.port_no)
		self.send_event_to_observers(\
			event.EventPortDelete(Port(dp.id, dp.ofproto, ofpport)))

		if not self.link_discovery:
			return

		port = self._get_port(dp.id, ofpport.port_no)
		if port and not port.is_reserved():
			self.ports.del_port(port)
			self._link_down(port)
			self.lldp_event.set()

	else:
		assert reason == dp.ofproto.OFPPR_MODIFY
		# LOG.debug('A port was modified.' +
		# '(datapath id = %s, port number = %s)',
		# dp.id, ofpport.port_no)
		self.port_state[dp.id].modify(ofpport.port_no, ofpport)
		self.send_event_to_observers(\
			event.EventPortModify(Port(dp.id, dp.ofproto, ofpport)))

		if not self.link_discovery:
			return

		port = self._get_port(dp.id, ofpport.port_no)
		if port and not port.is_reserved():
			if self.ports.set_down(port):
				self._link_down(port)
			self.lldp_event.set()

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        timestamp = datetime.now()
        self.analyzer.analyze(ev, timestamp.second + (timestamp.microsecond * 1e-6))
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def lldp_packet_in_handler(self, ev):
        msg = ev.msg
        
        try:
            src_dpid, src_port_no = LLDPPacket.lldp_parse(msg.data)
            
        except LLDPPacket.LLDPUnknownFormat as e:
            # This handler can receive all the packtes which can be
            # not-LLDP packet. Ignore it silently
            #print("Not LLDP Packet")
            return

        dst_dpid = msg.datapath.id
        if msg.datapath.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            dst_port_no = msg.in_port
        elif msg.datapath.ofproto.OFP_VERSION >= ofproto_v1_2.OFP_VERSION:
            dst_port_no = msg.match['in_port']
        else:
            LOG.error('cannot accept LLDP. unsupported version. %x',
                      msg.datapath.ofproto.OFP_VERSION)

        src = self._get_port(src_dpid, src_port_no)
        if not src or src.dpid == dst_dpid:
            return
        try:
            self.ports.lldp_received(src)
        except KeyError:
            # There are races between EventOFPPacketIn and
            # EventDPPortAdd. So packet-in event can happend before
            # port add event. In that case key error can happend.
            # LOG.debug('lldp_received: KeyError %s', e)
            pass

        dst = self._get_port(dst_dpid, dst_port_no)
        if not dst:
            return

        old_peer = self.links.get_peer(src)
        # LOG.debug("Packet-In")
        # LOG.debug("  src=%s", src)
        # LOG.debug("  dst=%s", dst)
        # LOG.debug("  old_peer=%s", old_peer)
        if old_peer and old_peer != dst:
            old_link = Link(src, old_peer)
            self.send_event_to_observers(event.EventLinkDelete(old_link))

        link = Link(src, dst)
        if link not in self.links:
            self.send_event_to_observers(event.EventLinkAdd(link))

        if not self.links.update_link(src, dst):
            # reverse link is not detected yet.
            # So schedule the check early because it's very likely it's up
            self.ports.move_front(dst)
            self.lldp_event.set()
            
    def send_lldp_packet(self, port):
        try:
            port_data = self.ports.lldp_sent(port)
        except KeyError as e:
            # ports can be modified during our sleep in self.lldp_loop()
            # LOG.debug('send_lldp: KeyError %s', e)
            return
        if port_data.is_down:
            return

        dp = self.dps.get(port.dpid, None)
        if dp is None:
            # datapath was already deleted
            return

        # LOG.debug('lldp sent dpid=%s, port_no=%d', dp.id, port.port_no)
        # TODO:XXX
        if dp.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            actions = [dp.ofproto_parser.OFPActionOutput(port.port_no)]
            dp.send_packet_out(actions=actions, data=port_data.lldp_data)
        elif dp.ofproto.OFP_VERSION >= ofproto_v1_2.OFP_VERSION:
            actions = [dp.ofproto_parser.OFPActionOutput(port.port_no)]
            out = dp.ofproto_parser.OFPPacketOut(
                datapath=dp, in_port=dp.ofproto.OFPP_CONTROLLER,
                buffer_id=dp.ofproto.OFP_NO_BUFFER, actions=actions,
                data=port_data.lldp_data)
            dp.send_msg(out)
        else:
            LOG.error('cannot send lldp packet. unsupported version. %x',
                      dp.ofproto.OFP_VERSION)

    def lldp_loop(self):
        while self.is_active:
	    self.lldp_event.clear()
            now = time.time()
            timeout = None
            ports_now = []
            ports = []
            for (key, data) in self.ports.items():
                if data.timestamp is None:
                    ports_now.append(key)
                    continue

                expire = data.timestamp + self.LLDP_SEND_PERIOD_PER_PORT
                if expire <= now:
                    ports.append(key)
                    continue

                timeout = expire - now
                break

            for port in ports_now:
                self.send_lldp_packet(port)
            for port in ports:
                self.send_lldp_packet(port)
                hub.sleep(self.LLDP_SEND_GUARD)      # don't burst

            if timeout is not None and ports:
                timeout = 0     # We have already slept
            # LOG.debug('lldp sleep %s', timeout)
            self.draw_graph(.2, draw=True)
            self.lldp_event.wait(timeout=timeout)
	
    def link_loop(self):
        while self.is_active:
	    self.link_event.clear()
            now = time.time()
	    deleted = []
            for (link, timestamp) in self.links.items():
	        # LOG.debug('%s timestamp %d (now %d)', link, timestamp, now)
	        if timestamp + self.LINK_TIMEOUT < now:
		    src = link.src
		    if src in self.ports:
		        port_data = self.ports.get_port(src)
			# LOG.debug('port_data %s', port_data)
			if port_data.lldp_dropped() > self.LINK_LLDP_DROP:
		            deleted.append(link)

	    for link in deleted:
	        self.links.link_down(link)
		# LOG.debug('delete %s', link)
		self.send_event_to_observers(event.EventLinkDelete(link))

		dst = link.dst
		rev_link = Link(dst, link.src)
		if rev_link not in deleted:
			# It is very likely that the reverse link is also
			# disconnected. Check it early.
			expire = now - self.LINK_TIMEOUT
			self.links.rev_link_set_timestamp(rev_link, expire)
			if dst in self.ports:
				self.ports.move_front(dst)
				self.lldp_event.set()
		
	    self.link_event.wait(timeout=self.TIMEOUT_CHECK_PERIOD)
	
	#Adds or removes an IP flow from each switch
	def _modify_blacklist(self, ipaddr, mode, dl_type=0x800):
       	    res = dot_to_dec(ipaddr)
    	    match = datapath.ofproto_parser.OFPMatch(dl_type=dl_type, nw_src=res)
	    if mode == "add":
		if ipaddr in self.blacklist:
		    return
	    	self.blacklist.append(ipaddr)
	    elif mode == "rmv":
		if ipaddr not in self.blacklist:
		    return
		self.blacklist.remove(ipaddr)
	    
	    for dp in self.dps:
	        datapath = self.dps[dp]
		ofproto = datapath.ofproto
		if mode == "add":
		    command = ofproto.OFPFC_ADD
		elif mode == "rmv":
		    command = ofproto.OFPFC_DELETE
		mod = datapath.ofproto_parser.OFPFlowMod(datapath=datapath, match=match,\
                                cookie=0,command=command, idle_timeout=0, hard_timeout=0,\
                                priority=ofproto.OFP_DEFAULT_PRIORITY+5,\
                                flags=ofproto.OFPFF_SEND_FLOW_REM, actions=None)

                datapath.send_msg(mod)			
	
	#Changes transmission rate on a switch's port -- meant for HP switches
	#@todo: make more general? Throttle switches that see an IP address
	def _modify_throttle(self, switch_ip, port, mode, username="manager", password="ccw"):
	    if mode == "add":
		if ipaddr in self.throttle_list:
		    return
		self.throttle_list.append((switch, port))
		command = 'interface ethernet' + `port` + ' rate-limit all out kbps 10000'
	    elif mode == "rmv":
		if ipaddr not in self.throttle_list:
		    return
		self.throttle_list.remove((switch, port))
		command = 'no interface ethernet' + `port` + ' rate-limit all out kbps 10000'
	    
	    print("Starting throttle command")
	    s = pexpect.spawn("ssh %s@%s" %(username, switch_ip))
	    s.expect('.*assword: ')
            # Send the password
            s.sendline(password)
            s.expect('Press any key to continue')
            # Send the return key
            s.send('\r')
            s.sendline('config \n')
            s.sendline(command)
            s.sendline('logo')
            s.sendline('y')
            print('Successful')

	    
	        
class Analyzer:

	def __init__(self):
		self.timestep = 1
		self.dpid_to_node = {0x00012c59e5107640:1, 0x0001c4346b94a200:2,\
					 0x0001c4346b99dc00:4, 0x0001c4346b946200:5,\
					 0x0001c4346b971ec0:6, 0x0001f0921c219d40:13}

		self.name_to_index = {1:0, 2:1, 3:2, 4:3, 5:4, 6:5, 8:6, 11:7, 12:8,\
					13:9, 14:10}		
		self.colors = {0:"Blue", 1:"BlueViolet", 2:"CadetBlue", 3:"Coral", 4:"DarkGreen",\
                		5:"DarkGoldenRod", 6:"DarkRed", 7:"DarkTurquoise",\
				 8:"DarkOliveGreen", 9:"DeepSkyBlue", 10:"FireBrick"}
		self.names = {0:'Chicago', 1:'Sunnyvale', 2:'Los Angeles', 3:'Salt Lake City', 4:'Denver',\
            			5:'El Paso', 6:'D.C.', 7:'Kansas City', 8:'Seattle', 9:'Houston',\
             			10:'Nashville'}
		self.links = {(1,14):Link(1,14), (1,8):Link(1,8),\
				(1,11):Link(1,11), (1,12):Link(1,12),\
				(2,3):Link(2,3), (2,12):Link(2,12),\
				(4,5):Link(4,5), (4,3):Link(4,3),\
				(4,12):Link(4,12), (5,11):Link(5,11),\
				(5,6):Link(5,6), (6,13):Link(6,13),\
				(6,3):Link(6,3), (13,14):Link(13,14)}	
		
		self.disconnected_links = set([(2,3), (6,3), (1,11), (13,14)])
		for link in self.disconnected_links:
			self.links[link].updated = True
		
		self.times = []
		self.evalues = {0:[], 1:[], 2:[], 3:[], 4:[], 5:[], 6:[],\
				7:[], 8:[], 9:[], 10:[]}
		self.lines = [0,0,0,0,0,0,0,0,0,0,0]
		#fig = plt.figure()
		#fig.patch.set_facecolor("#E9E9E9")
		#plt.xlabel("Time")
		#plt.ylabel("Eigenvalues")
		#plt.title("$\\lambda$ - Values Over Time (Online)")
		adj = self.create_adj()
		L = matlib.zeros((11,11))
                np.fill_diagonal(L, np.array(sum(adj)))
                L -= adj
		self.initialL = L
		
		#Create a separate plotting thread for online plotting
		self.parent_conn, child_con = Pipe()
		self.plotting_thread = Process(target=self.plot, args=(child_con, ))
		self.plotting_thread.start()

	def analyze(self, ev, time):
		switch = self.dpid_to_node[ev.msg.datapath.id]
		for stat in sorted(ev.msg.body, key=attrgetter('port_no')):
			port, rx_b, tx_b = stat.port_no, stat.rx_bytes, stat.tx_bytes
			if (switch,port) in self.links and (switch,port) not in\
			    self.disconnected_links:
				link = self.links[(switch,port)]
				link.elapse_time([rx_b, tx_b], time)
				link.updated = True
		
		all_updated = True
		for link in self.links:
			if not self.links[link].updated:
				all_updated = False
				break
		
		if all_updated:
			self.spectral_analysis()
			
			for link in self.links:
				if link not in self.disconnected_links:
					self.links[link].updated = False
			self.timestep += 1
	
	def spectral_analysis(self):
		data = []
		adj = self.create_adj()
		L = matlib.zeros((11,11))
		np.fill_diagonal(L, np.array(sum(adj)))
		L -= adj
		Dnow, Vnow = np.linalg.eig(L)
		idx = Dnow.argsort()
		Dnow = Dnow[idx]
		Vnow = Vnow[:,idx]
		self.times.append(self.timestep)
		data.append(self.timestep)
		data.append({})
		for i in range(11):
			self.evalues[i].append(Dnow[i])
			data[1][i] = Dnow[i]			
		self.write_matrix(Vnow, "V")
		self.write_value(Dnow)
		self.write_matrix(L, "L")
		self.parent_conn.send(data)
		
	def create_adj(self):
		adj = matlib.zeros((11,11))
		for link in self.links:
			link = self.links[link]
			adj[self.name_to_index[link.src],self.name_to_index[link.dst]] =\
				link.weight
			adj[self.name_to_index[link.dst],self.name_to_index[link.src]] =\
				link.weight
		return adj

	def write_matrix(self, matrix, file_name):
                f = open(file_name, "a")
                for vect in matrix:
                        for i in range(11):
                               f.write(`vect[(0,i)]` + " ")
                        f.write("\n")
                f.write("\n")
                f.flush()
                f.close()

	def write_value(self, valuesIn):
		values = open("D", "a")
    		for value in valuesIn:
        		values.write(`value` + " ")
    		values.write("\n")
		values.flush()
		values.close()

	def plot(self, child_con):
	    times = []
	    evalues = {0:[], 1:[], 2:[], 3:[], 4:[], 5:[], 6:[],\
			7:[], 8:[], 9:[], 10:[]}
	    lines = [0,0,0,0,0,0,0,0,0,0,0]
            colors = {0:"Blue", 1:"BlueViolet", 2:"CadetBlue", 3:"Coral", 4:"DarkGreen",\
                                5:"DarkGoldenRod", 6:"DarkRed", 7:"DarkTurquoise",\
                                 8:"DarkOliveGreen", 9:"DeepSkyBlue", 10:"FireBrick"}
            names = {0:'Chicago', 1:'Sunnyvale', 2:'Los Angeles', 3:'Salt Lake City', 4:'Denver',\
                                5:'El Paso', 6:'D.C.', 7:'Kansas City', 8:'Seattle', 9:'Houston',\
                                10:'Nashville'}

	    while True:
	        try:
		    data = child_con.recv()
		    
		    times.append(data[0])
		    for i in range(11):
			evalues[i].append(data[1][i])
		    if len(times) > 20:
		    	    times.pop(0)
			    for i in range(11):
				evalues[i].pop(0)
		    plt.xlim(min(times),max(times))
		    ys = [max(evalues[i]) for i in range(11)]
	 	    plt.ylim(-5, max(ys)+5)
		    for i in range(11):
			    line, = plt.plot(times, evalues[i],\
					color=colors[i], label=names[i])
			    lines[i] = line

		    plt.legend(handles=lines)
		    #plt.draw()
		    plt.pause(2)
		    for line in lines:
			    line.remove()	
		except IOError:
		    continue
