import logging
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls, DEAD_DISPATCHER
from ryu.lib import hub
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
import pexpect
from gi.repository import Gtk
from DHCPFingerprint import *
from datetime import datetime
import numpy as np
import matplotlib.pyplot as plt
import time
from cassandra.cluster import Cluster
from dpid_map import map_switch_dpid
from utils import *
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
	self.switch_ports = {}
	
        self.dpid_to_ip = {}
        self.dpid_to_node = {0x00012c59e5107640:1, 0x0001c4346b94a200:2,\
                                         0x0001c4346b99dc00:4, 0x0001c4346b946200:5,\
                                         0x0001c4346b971ec0:6, 0x0001f0921c219d40:13}

        #SDN Application data structures
        self.blacklist = []
        self.throttle_list = []

        #SDN Application Flags
        self.fingerprint = False
        self.topology = True
        self.analyze = False 

        #threads
        self.analyzer = Analyzer()
        self.lldp_event = hub.Event()
        self.link_event = hub.Event()
        self.threads.append(hub.spawn(self.lldp_loop))
        self.threads.append(hub.spawn(self.link_loop))
        self.parent_conn, child_con = Pipe()
        self.gui_thread = Process(target=self._gui, args=(child_con,))
        self.gui_thread.start()
        self.threads.append(hub.spawn(self._monitor))

        self.throttle_list = []
        with open('V','w') as f:
            f.flush()
        with open('D','w') as f:
            f.flush()
        with open('L','w') as f:
            f.flush()	


    def _gui(self, connection):
        class App(Gtk.Window):
            def __init__(self, connection):
                self.connection = connection
                Gtk.Window.__init__(self, title="Red Button")
                box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
                button = Gtk.Button("Fingerprint")
                button.connect("clicked", self.send_msg, "activate fingerprint")
                box.pack_start(button, True, True, 0)
		button = Gtk.Button("Full Graph")
                button.connect("clicked", self.send_msg, "activate fingerprint")
		box.pack_start(button, True, True, 0)
                button = Gtk.Button("Spanning Tree")
                button.connect("clicked", self.send_msg, "app blacklist")
                box.pack_start(button, True, True, 0)
                self.add(box)
            def send_msg(self, button, data):
                self.connection.send(data)
                self.connection.send("\n")

        win = App(connection)
        win.connect("delete-event", Gtk.main_quit)
        win.show_all()
        Gtk.main()

    #Todo: Add listener and messages
    def _monitor(self):
        while True:
            try:
                msg = self.parent_conn.recv()
		print(msg)
		msg = msg.split()
                if msg[0] == "activate":
                    if msg[1] == "fingerprint":
                        self.fingerprints = {}
			self.fingerprint_list = createFingerPrintList('/ryu/ryu/app/Mid/fingerprint.xml')
			self.cluster = Cluster()
                        self.session = self.cluster.connect('fingerprints')
                        db = self.session.execute_async("select * from fpspat")
			#import IPython
			#IPython.embed()
                        for row in db.result():
                            mac_addr = row.mac
			    print(row)
                            self.fingerprints[mac_addr] = {'ip':row.ip, 'os':row.os,\
                                            'switch':row.switch, 'port':row.port,\
                                            'hostname':row.hostname, 'history':row.history}
            		
			self.fingerprint = True
		if msg[0] == "app":
		    if msg[1] == "blacklist":
			self._modify_blacklist("10.10.13.78", "add")
	    except:
                hub.sleep(2)
	    hub.sleep(2)
              
     #          self.fingerprint_list = []
            # for dp in self.dps:
            #     if dp in self.dpid_to_node:
            #         self._request_port_stats(self.dps[dp])
            # hub.sleep(2)
    
    def draw_graph(self, timeout, draw=False):
	G = nx.Graph()

        plt.clf()
        labels = {}
        nodes = []
        for id in self.dpids:
            G.add_node(hex(id))
            labels[hex(id)] = hex(id)
            nodes.append(hex(id))

        for link in self.links:
            G.add_edge(hex(link.src.dpid), hex(link.dst.dpid))
        self.graph = G.copy()
        pos = nx.spring_layout(G)
	
	for node in nodes:
            G.remove_node(node)
	
	if not draw:
            nx.draw(G)
            nx.draw_networkx_nodes(G, pos, nodelist=nodes, node_color='FireBrick',\
                                node_size=500, alpha=0.8)
	    for link in self.links:
                G.add_edge(hex(link.src.dpid), hex(link.dst.dpid))

	    nx.draw_networkx_edges(G, pos)
     	    plt.pause(timeout)

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

        self.dpids[dp.id] = dp
        if dp.id not in self.port_state:
            self.port_state[dp.id] = PortState()
            for port in dp.ports.values():
                self.port_state[dp.id].add(port.port_no, port)

    def _unregister(self, dp):
        if dp.id in self.dpids:
            del self.dpids[dp.id]
            del self.port_state[dp.id]

    def _get_switch(self, dpid):
        if dpid in self.dpids:
            switch = Switch(self.dpids[dpid])
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
            if datapath.id in self.dpids:
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
            if datapath.id in self.dpids:
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
    def app_packet_in_handler(self, ev):
        msg = ev.msg
        if self.fingerprint:
	    self._dhcp_handler(msg)

        if self.topology:
            self._lldp_handler(msg)

    def _dhcp_handler(self, msg):
        dpid = hex(msg.datapath.id)
        pkt = msg.data
        try:
            source_mac, parsedPacket = dhcp_parse(pkt)
	    print("DHCP Packet")
        except TypeError:
            return 

        hitlist = compare(self.fingerprint_list,parsedPacket)

        hostname = get_dhcp_option_value(parsedPacket[12], 12)
        option53 = get_dhcp_option_value(parsedPacket[12], 53)
        option60 = get_dhcp_option_value(parsedPacket[12], 60)
        if option53:
            dhcptype = dhcp_types[option53]
            if dhcptype != "Discover" and dhcptype != "Request":
                print("Not a request of discover packets, so ignoring")
                return
        if parsedPacket[2]:
            source_ip = hex_to_ip(hex(parsedPacket[2]))
        elif parsedPacket[16]:
            source_ip = hex_to_ip(hex(parsedPacket[16]))
        elif get_dhcp_option_value(parsedPacket[12], 50):
            source_ip = map(ord, get_dhcp_option_value(parsedPacket[12], 50))
            source_ip = '.'.join(str(x) for x in source_ip)
        else:
            source_ip = None

        mac = hex_to_mac(source_mac)

        ### NPS CCW Specific Network ###
        location = DPIDToLocation(dpid)#
        port = str(msg.in_port)        # 
        ################################

        if mac not in self.fingerprints:
            print("New fingerprint")
            print "Source MAC: {}".format(mac)
            print "IP Address: {}".format(source_ip)
            print "Location  : {}".format(location)
            print "Host name : {}".format(hostname)
            print "DHCP Type : {}".format(dhcptype)
            mac_history = ["[%s, %s, %s, %s, %s]" % (source_ip, hitlist[0][0],\
                            location, port, hostname)]
            self.fingerprints[mac] = {'ip':source_ip, 'os':hitlist[0][0],\
                                            'switch':location, 'port':port,\
                                            'hostname':hostname, 'history':mac_history}
            command = "insert into fpspat (MAC, IP, OS, Switch, Port, Hostname,\
                        Time, History) values ('{0}', '{1}', '{2}', '{3}', '{4}',\
                        '{5}', '{6}', {7})".format(mac, source_ip, hitlist[0][0],\
                        location, port, hostname, str(datetime.now()),\
                        mac_history)
            self.session.execute(command)
        
        fp = self.fingerprints[mac]
        changes = []
        time = str(datetime.now())
	skip_switch = False
        for prop,val in [('ip', source_ip), ('os', hitlist[0][0]),\
                        ('port', port),('switch', location),('hostname', hostname)]:
            if fp[prop] != val:
		if prop == "port":
		    try:
		        if port in self.switch_ports[dpid]:
			    skip_switch = True
			    print("Repeat DHCP")
			    continue
		    except:
			print("DPID not set up yet")
			skip_switch = True
			continue
		if prop == "switch":
		    print(port)
		    if skip_switch:
			continue
                print("The " + prop + " changed")
                changes.append("[" + fp[prop] + " changed to " + val + " at time " + time + "]")
                fp[prop] = val
                command = "update fpspat set " + prop + " = " + val + " where MAC = " + mac
                print(command)
		self.session.execute(command)

        if changes:
            print("Database updated to reflect changes")
            fp['history'] += changes
            command = "update fpspat set History = '{0}' where MAC= '{1}'".format(fp['history'], mac)
            self.session.execute(command)


    def _lldp_handler(self, msg):
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
        if old_peer and old_peer != dst:
            old_link = Link(src, old_peer)
            self.send_event_to_observers(event.EventLinkDelete(old_link))

        link = Link(src, dst)
        if link not in self.links:
            self.send_event_to_observers(event.EventLinkAdd(link))
	    if src_dpid not in self.switch_ports:
		self.switch_ports[src_dpid] = []
	    if src_port_no not in self.switch_ports[src_dpid]:
	        self.switch_ports[src_dpid].append(src_port_no)
	    if dst_dpid not in self.switch_ports:
		self.switch_ports[dst_dpid] = []
	    if dst_port_no not in self.switch_ports[dst_dpid]:
		self.switch_ports[dst_dpid].append(dst_port_no)

        if not self.links.update_link(src, dst):
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

        dp = self.dpids.get(port.dpid, None)
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
		if link.dst.port_no in self.switch_ports[link.dst.dpid]:
		    self.switch_ports[link.dst.dpid].remove(link.dst.port_no)
		if link.src.port_no in self.switch_ports[link.src.dpid]:
		    self.switch_ports[link.src.dpid].remove(link.src.port_no)

	    self.link_event.wait(timeout=self.TIMEOUT_CHECK_PERIOD)
	
    #Adds or removes an IP flow from each switch
    def _modify_blacklist(self, ipaddr, mode, dl_type=0x800):
       	res = dot_to_dec(ipaddr)

	if mode == "add":
	    if ipaddr in self.blacklist:
	        return
	    self.blacklist.append(ipaddr)
	elif mode == "rmv":
	    if ipaddr not in self.blacklist:
	        return
	    self.blacklist.remove(ipaddr)
	print(self.blacklist)
	for dp in self.dpids:
	    datapath = self.dpids[dp]
	    ofproto = datapath.ofproto
            match = datapath.ofproto_parser.OFPMatch(dl_type=dl_type, nw_src=res)

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
