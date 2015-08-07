
import logging
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls, DEAD_DISPATCHER
from ryu.lib import hub
from ryu.lib.ip import ipv4_to_bin
from Link import Link, LinkState
from Switch import Switch
from LLDPPacket import LLDPPacket
from Port import Port, PortState, PortData, PortDataState
import Routing
from ryu.ofproto import ofproto_v1_0
from ryu.lib import addrconv, hub
from ryu.lib.mac import DONTCARE_STR
from ryu.ofproto.ether import ETH_TYPE_LLDP
from ryu.topology import event
from ryu.ofproto import nx_match

import time

import networkx as nx
import pexpect
from DHCPFingerprint import *
from ryu.lib.packet import packet, ethernet, lldp, arp, dhcp, icmp, ipv4

from datetime import datetime
import matplotlib.pyplot as plt
import time
from cassandra.cluster import Cluster
from dpid_map import map_switch_dpid
from utils import *
from pexpect import spawn
from random import randint, shuffle
import signal
from os import system
from Analyzer import Analyzer

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
	
        self.dpid_to_ip = map_switch_dpid()

        #NPS SDN Specific Dictionary##################################################
        self.dpid_to_node = {0x00012c59e5107640:1, 0x0001c4346b94a200:2,\
                                         0x0001c4346b99dc00:4, 0x0001c4346b946200:5,\
                                         0x0001c4346b971ec0:6, 0x0001f0921c219d40:13}
        ##############################################################################

        self.active_ips = {}
        self.arp_table = {}

        #SDN Application data structures
        self.blacklist = []
        self.throttle_list = []

        #SDN Application Flags
        #This call assigns self.analyze, self.topology,
        #and self.fingerprint and sets up those apps
        self._n_fingerprint = True
        self._n_topology = True
        self._n_analyze = True
        self._load_settings()
        
        #Listen for a signal that tells the controller to update
        #its settings.  This is really tempramental.
        #signal.signal(signal.SIGUSR1, self._load_settings)
        self.threads.append(hub.spawn(self._monitor))
        self.threads.append(hub.spawn(self._listener))

        self.throttle_list = []

    def _load_settings(self, signal=None, frame=None):
	print("Loading the settings file")
        with open("control_node_settings", "r") as f:
            for line in f.readlines():
                exec(line)

        # If the fingerprint app is checked to run and has not been run yet,
        # then do all the following.
        if self.fingerprint and self._n_fingerprint:
            self._n_fingerprint = False
            self.fingerprints = {}
            self.fingerprint_list = createFingerPrintList('fingerprint.xml')
            self.cluster = Cluster()
            self.session = self.cluster.connect('fingerprints')
            db = self.session.execute_async("select * from fpspat")
            for row in db.result():
                mac_addr = row.mac
                self.fingerprints[mac_addr] = {'ip':row.ip, 'os':row.os,\
                                                'switch':row.switch, 'port':row.port,\
                                                'hostname':row.hostname, 'history':row.history}
            print("Downloaded Fingerprint Database \n")

        
        if self.analyze and self._n_analyze:
            self.analyzer = Analyzer()
            self._n_analyze = False
            with open('V','w') as f:
                f.flush()
            with open('D','w') as f:
                f.flush()
            with open('L','w') as f:
                f.flush()
        if self.topology and self._n_topology:
            self._n_topology = False
            self.lldp_event = hub.Event()
            self.link_event = hub.Event()
            self.threads.append(hub.spawn(self.lldp_loop))
            self.threads.append(hub.spawn(self.link_loop))
 


    
    def _listener(self):
        """
        This function will continuously open a file
        named 'commands' and execute each line in 
        that file and then clear the file.  If a 
        command fails, then the file is not cleared,
        so be wary of that.
        """
        while True:
            with open("commands", "r") as f:
                for line in f.readlines():
                    exec(line)
            with open("commands", "w") as f:
                f.flush()
            hub.sleep(2)

    def _monitor(self):
        """
        Runs the monitor app which collects data from the network.
        Will only run if "analyze" is clicked on the GUI's 
        splash screen.
        """
        if self.topology:
            while self.dpids == {}:
        	print("Waiting for live datapaths")
        	hub.sleep(2)
	    #self.map_hosts()

        while True:
            if self.analyze:
                for dp in self.dpids:
                    if dp in self.dpid_to_node:
                       self._request_port_stats(self.dpids[dp])
      	    if self.topology:
		self.draw_graph(1, draw=True)  
            hub.sleep(2)

##################################
#  ARP and ICMP Packet Handlers  #
##################################
    def _handle_arp_rq(self, dst_ip):
    	pkt = packet.Packet()
    	pkt.add_protocol(ethernet.ethernet(ethertype=0x806,\
                                               dst='ff:ff:ff:ff:ff:ff',\
                                               src=self.hw_addr))
        pkt.add_protocol(arp.arp(opcode=arp.ARP_REQUEST,\
                                 src_mac=self.hw_addr,\
                                 src_ip=self.ip_addr,\
                                 dst_mac='00:00:00:00:00:00',\
                                 dst_ip=dst_ip))
        self._flood_packet(pkt)
    

    def _handle_icmp_reply(self, pkt_icmp, pkt_ipv4, datapath):
        if pkt_icmp.type != icmp.ICMP_ECHO_REPLY: return
        if pkt_ipv4.dst != self.ip_addr:
            print(pkt_ipv4.dst, self.ip_addr) 
            return
        print("------------------------")
        print("PING RECEIVED THANK GOD")
        print(pkt_ipv4.src)
        print(pkt_ipv4.dst)
        print(datapath.id)
        print("------------------------")

    #Finish ARP redesignation
    def _handle_arp_reply(self, pkt_arp, port, dpid):
        if pkt_arp.opcode == arp.ARP_REPLY and pkt_arp.dst_mac == self.hw_addr:
            if pkt_arp.src_ip not in self.active_ips:
                print("ARP from " + pkt_arp.src_ip + "\n")
                self.active_ips[pkt_arp.src_ip] =  [dpid, port]
                self.arp_table[pkt_arp.src_ip] = pkt_arp.src_mac
                if self.topology:
                    self.draw_graph(1, draw=True)
        if pkt_arp.opcode == arp.ARP_REQUEST and pkt_arp.src_ip != self.ip_addr:
        #print("ARP Reqest from: " + pkt_arp.src_mac + " requesting: " + pkt_arp.dst_ip)
            if pkt_arp.dst_ip not in self.arp_table: return
            #construct and send ARP reply
            reply_pkt = packet.Packet()
            reply_pkt.add_protocol(ethernet.ethernet(ethertype=0x806,\
                                               dst=pkt_arp.src_mac,\
                                               src=self.arp_table[pkt_arp.dst_ip]))
            reply_pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,\
                                 src_mac=self.arp_table[pkt_arp.dst_ip],\
                                 src_ip=pkt_arp.dst_ip,\
                                 dst_mac=pkt_arp.src_mac,\
                                 dst_ip=pkt_arp.src_ip))
            print("Responded to ARP Request: " )
            print("Gave [" + pkt_arp.src_mac + "," + pkt_arp.src_ip + "]" +\
            "[" + pkt_arp.dst_ip + "," + self.arp_table[pkt_arp.dst_ip] + "]") 
            self._send_packet(reply_pkt, self.dpids[int(dpid, 16)]) 


#############################
#  How to send out packets  #
#############################

    def _flood_packet(self, pkt):
    	for dpid in self.dpids:
    	    datapath = self.dpids[dpid]
    	    ofproto = datapath.ofproto
    	    actions = [datapath.ofproto_parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
       	    pkt.serialize()
    	    out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=0xffffffff,\
    						in_port=ofproto.OFPP_CONTROLLER, actions=actions,\
    						data=pkt.data)
    	    datapath.send_msg(out)
    
    def _send_packet(self, pkt, datapath=None):
	#Pick a random datapath to send from	
        if not datapath:
	    datapath = self.dpids[self.dpids.keys()[randint(0,len(self.dpids)-1)]]
        ofproto = datapath.ofproto
	pkt.serialize()
	ether_pkt = pkt.get_protocol(ethernet.ethernet)
	if ether_pkt.dst in self.mac_to_port[datapath.id]:
	    print("Sending packet out: " + `self.mac_to_port[datapath.id][ether_pkt.dst]`)
            actions = [datapath.ofproto_parser.OFPActionOutput(self.mac_to_port[datapath.id]\
							[ether_pkt.dst])]
            out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=0xffffffff,\
                                                in_port=ofproto.OFPP_CONTROLLER, actions=actions,\
                                                data=pkt.data)
            datapath.send_msg(out)

##########################
#  How to draw a graph  #
#########################
    def draw_graph(self, timeout, draw=False):
        """
        This function does the actual drawing of the 
        network topology.
        """
    	G = nx.Graph()

        plt.clf()
        labels = {}
        nodes = []
    	host_nodes = []
        for id in self.dpids:
            G.add_node(hex(id))
            labels[hex(id)] = hex(id)
            nodes.append(hex(id))

    	
        for link in self.links:
            G.add_edge(hex(link.src.dpid), hex(link.dst.dpid))
    	for ip in self.active_ips:
    	    if ip not in host_nodes:
    	    	G.add_node(ip)
    	    	G.add_edge(self.active_ips[ip][0], ip)
    		host_nodes.append(ip)

        self.graph = G.copy()
        pos = nx.spring_layout(G)
    	
    	G = nx.Graph()
    	
    	if draw:
            nx.draw(G)
            nx.draw_networkx_nodes(G, pos, nodelist=nodes, node_color='FireBrick',\
                                    node_size=500, alpha=0.8)
    	    nx.draw_networkx_nodes(G, pos, nodelist=host_nodes, node_color='DarkGoldenRod',\
    				node_size=200, alpha=0.8)

    	    for link in self.links:
                    G.add_edge(hex(link.src.dpid), hex(link.dst.dpid))
    	    for ip in self.active_ips:
    		G.add_edge(self.active_ips[ip][0],ip)

    	    nx.draw_networkx_edges(G, pos)
            plt.pause(timeout)


##########################
#  How to create a flow  #
##########################

    def _create_icmp_flow(self,datapath):
        ofproto = datapath.ofproto
        ofproto_parser = datapath.ofproto_parser
        nw_dst = struct.unpack('!I', ipv4_to_bin(self.ip_addr))[0]    
        match = datapath.ofproto_parser.OFPMatch(dl_type=0x800, nw_dst=nw_dst)
        actions = [datapath.ofproto_parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        mod = datapath.ofproto_parser.OFPFlowMod(
                datapath=datapath, match=match, cookie=0, command=ofproto.OFPFC_ADD,
                idle_timeout=0, hard_timeout=0, actions=actions,
                priority=0xFFFF)
        datapath.send_msg(mod)

    def _create_lldp_flow(self, datapath):
        ofproto = datapath.ofproto
        ofproto_parser = datapath.ofproto_parser        
        if ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            #Add LLDP Rule
            match = datapath.ofproto_parser.OFPMatch(dl_type=0x88cc)
            actions = [datapath.ofproto_parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
            mod = datapath.ofproto_parser.OFPFlowMod(
                        datapath=datapath, match=match, cookie=0, command=ofproto.OFPFC_ADD,
                        idle_timeout=0, hard_timeout=0, actions=actions,
                        priority=0xFFFF)
            datapath.send_msg(mod)

    def _create_arp_flow(self, datapath):
        ofproto = datapath.ofproto
        ofproto_parser = datapath.ofproto_parser
        match = datapath.ofproto_parser.OFPMatch(dl_type=0x0806)
        actions = [datapath.ofproto_parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        mod = datapath.ofproto_parser.OFPFlowMod(
                datapath=datapath, match=match, cookie=0, command=ofproto.OFPFC_ADD,
                idle_timeout=0, hard_timeout=0, actions=actions,
                priority=0xFFFF)
        datapath.send_msg(mod)


###################################
#  How to use Ryu Event Handlers  #
###################################	

    @set_ev_cls(ofp_event.EventOFPStateChange,
            [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath

        if ev.state == MAIN_DISPATCHER:
            
            dp_multiple_conns = False
            if datapath.id in self.dpids:
                dp_multiple_conns = True
            
            self.logger.debug('register datapath: %016x', datapath.id)
            print("New DPID: " + hex(datapath.id))

            self._register(datapath)
            switch = self._get_switch(datapath.id)

            if not dp_multiple_conns:
                self.send_event_to_observers(event.EventSwitchEnter(switch))
                
            
            self._create_lldp_flow(datapath)
	    self._create_arp_flow(datapath)
    	    self._create_icmp_flow(datapath)


            if not dp_multiple_conns:
                for port in switch.ports:
                    if not port.is_reserved():
                        self._port_added(port)
                        
        elif ev.state == DEAD_DISPATCHER:
	    switch = self._get_switch(datapath.id)
            if datapath.id in self.dpids:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                self._unregister(datapath)
                self.send_event_to_observers(event.EventSwitchLeave(switch))
            
            for port in switch.ports:
                if not port.is_reserved():
                    self.ports.del_port(port)
                    self._link_down(port)
        if self.topology:
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
	pkt = packet.Packet(msg.data)
	pkt_dhcp = pkt.get_protocol(dhcp.dhcp)
	pkt_arp = pkt.get_protocol(arp.arp)
	pkt_icmp = pkt.get_protocol(icmp.icmp)
	pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
	if pkt_icmp:
	    self._handle_icmp_reply(pkt_icmp, pkt_ipv4, msg.datapath)
	if pkt_arp:
            self._handle_arp_reply(pkt_arp, ev.msg.in_port, hex(msg.datapath.id))   
        if self.fingerprint:
    	    if pkt_dhcp:
    		print("----------------------------------")
    		print(pkt_dhcp.yiaddr)
    		print(pkt_dhcp.op)
    		print("----------------------------------")
    	    self._dhcp_handler(msg)
		
        if self.topology:
            self._lldp_handler(msg)

#######################
#  DHCP Fingerprints  #
#######################

    def _dhcp_handler(self, msg):
        """
        Takes a DHCP packet and parses it for MAC, IP, Switch, Port, Options
        Using the options, this function checks those options against a 
        fingerprint database in order to guess the operating system used 
        by the host.  Afterwards, it stores that information in a 
        Cassandra database.
        """
        dpid = hex(msg.datapath.id)
        pkt = msg.data
        try:
            source_mac, parsedPacket = dhcp_parse(pkt)
		
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
        for prop,val in [('ip', source_ip), ('os', hitlist[0][0]),('hostname', hostname)]:
            if fp[prop] != val:
                print("The " + prop + " changed")
                changes.append("[" + fp[prop] + " changed to " + val + " at time " + time + "]")
                fp[prop] = val
                command = "update fpspat set " + prop + " = " + `val` + " where MAC = " + `mac`
                print(command)
		self.session.execute(command)

        if changes:
            print("Database updated to reflect changes")
            fp['history'] += changes
	    print(fp['history'])
            command = "update fpspat set History = '{0}' where MAC= '{1}'".format(str(fp['history']),\
		str(mac))
            self.session.execute(command)


#######################################
#  LLDP Portion - Topology Detection  #
#######################################
    def close(self):
        self.is_active = False
        if self.link_discovery:
            self.lldp_event.set()
        self.link_event.set()
        hub.joinall(self.threads)
            
    def _register(self, dp):
        """
        Takes the datapath and registers
        it as a switch.  This is how
        the controller represents the 
        switches.
        """
        assert dp.id is not None

        self.dpids[dp.id] = dp
        if dp.id not in self.port_state:
            self.port_state[dp.id] = PortState()
            for port in dp.ports.values():
                self.port_state[dp.id].add(port.port_no, port)

    def _unregister(self, dp):
        """
        This function is called when a switch
        dies. It helps with the book-keeping
        and clean up.
        """
        if dp.id in self.dpids:
            del self.dpids[dp.id]
            del self.port_state[dp.id]

    def _get_switch(self, dpid):
        """
        Returns the switch representation
        of the datapath id.
        """
        if dpid in self.dpids:
            switch = Switch(self.dpids[dpid])
            for ofpport in self.port_state[dpid].values():
                switch.add_port(ofpport)
            return switch

    def _get_port(self, dpid, port_no):
        """
        Returns the controller's representation of a port.
        """
        switch = self._get_switch(dpid)
        if switch:
            for p in switch.ports:
                if p.port_no == port_no:
                    return p

    def _port_added(self, port):
        """
        Adds the port to a list of ports used to 
        connect two switches.
        """
        lldp_data = LLDPPacket.lldp_packet(
            port.dpid, port.port_no, port.hw_addr, self.DEFAULT_TTL)
        self.ports.add_port(port, lldp_data)
        # LOG.debug('_port_added dpid=%s, port_no=%s, live=%s',
        #           port.dpid, port.port_no, port.is_live())

    def _link_down(self, port):
        """
        Creates an event that will tell the controller
        that the link state has changed so that the 
        controller can reflect that in its representation.
        """
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

    def _lldp_handler(self, msg):
        """
        Will react to LLDP packets by parsing then and creating 
        events so that the controller knows to update its topology
        representation.
        """
        try:
            # Attempt to parse the packet as an LLDP packet
            # Will fail if it is not an LLDP packet
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
        """
        Handles the crafting and sending of LLDP packets
        For each port on each switch, create a packet 
        unique to that (switch,port) combination.
        """
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
        """
        This function is how the topology is kept up to date.
        It will send out LLDP packets at every interval to
        update the topology.
        """
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
            self.draw_graph(1, draw=True)
            self.lldp_event.wait(timeout=timeout)
	
    def link_loop(self):
        """
        This function helps update the actual connection
        between switches.  I don't know the difference
        between this function and lldp_loop, but you
        need both of them, otherwise, the topology won't
        update.
        """
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

##################################
#   Application Implementations  #
##################################	

    def _request_port_stats(self, datapath):
        """
        Sends a message to each switch requesting
        port statistics.  This is used for network
        analytics.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_NONE)
        datapath.send_msg(req)


    #Adds or removes an IP flow from each switch
    def _modify_blacklist(self, ipaddr, mode, dl_type=0x800):
       	res = struct.unpack('!I', ipv4_to_bin(ipaddr))[0]
    	if mode == "add":
    	    if ipaddr in self.blacklist:
    	        return
	    self.blacklist.append(ipaddr)
    	elif mode == "remove":
    	    if ipaddr not in self.blacklist:
    	        return
	    self.blacklist.remove(ipaddr)

    	for dp in self.dpids:
    	    datapath = self.dpids[dp]
    	    ofproto = datapath.ofproto
            match = datapath.ofproto_parser.OFPMatch(dl_type=dl_type, nw_src=res)

    	    if mode == "add":
		print("Adding " + ipaddr + " to blacklist")
    	        command = ofproto.OFPFC_ADD
    	    elif mode == "remove":
		print("Removing " + ipaddr + " to blacklsit")
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
            if ipaddr in self.throttle_list: return
    	    self.throttle_list.append((switch, port))
    	    command = 'interface ethernet' + `port` + ' rate-limit all out kbps 10000'
    	elif mode == "rmv":
    	    if ipaddr not in self.throttle_list: return
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
        print('Throttle Successful')

    def clear_all_flows(self):
        for switch in [1,2,3,4,5,6,8,9,10,11,12,13,14]:
            print("Deleting flows on {}".format(switch))
            system("dpctl del-flows tcp:10.10.0.{}:6655".format(switch))
            
        for dp in self.dpids:
            datapath = self.dpids[dp]
            print("Adding flows onto {}".format(dp))
            self._create_lldp_flow(datapath)
        self._create_arp_flow(datapath)
        self._create_icmp_flow(datapath)
    
    def switch_on_all_ports(self,username="manager", password="ccw"):
        for dp in self.dpids:
            dp = hex(dp)
            print("logging into " + self.dpid_to_ip[dp])
            s = spawn("ssh %s@%s" %(username, self.dpid_to_ip[dp]))
            s.expect(".*assword")
            s.sendline(password)
            s.expect("Press any key to continue")
            s.sendline("\r")
            s.sendline("config")
            for n in range(1,25):
                #print("Enabling port " + `n` + " on " + self.dpid_to_ip[dp])
                s.sendline("interface ethernet " + `n` + " enable")
            s.sendline("save")
            s.sendline("logo")
            s.sendline("y")
        print("CREATED FULLY CONNECTED GRAPH")

    def create_spanning_tree(self, username="manager", password="ccw"):
        T = nx.minimum_spanning_tree(self.graph)

        used_links = []
        disabled_ports = {}

        for link in self.links:
            used = False
            src, dst = hex(link.src.dpid), hex(link.dst.dpid)
            for edge in T.edges():
                if (src,dst) == edge or (dst,src) == edge:
                    used = True
            if not used:
                if link.src.dpid not in disabled_ports:
                    disabled_ports[link.src.dpid] = []
                disabled_ports[link.src.dpid].append(link.src.port_no)
        for dp in disabled_ports:
            ip = self.dpid_to_ip[hex(dp)]
            print("logging into " + ip)
            s = spawn("ssh %s@%s" %(username, ip))
            s.expect(".*assword")
            s.sendline(password)
            s.expect("Press any key to continue")
            s.sendline("\r")
            s.sendline("config")
            for n in disabled_ports[dp]:
                #print("Enabling port " + `n` + " on " + self.dpid_to_ip[dp])
                s.sendline("interface ethernet " + `n` + " disable")
            s.sendline("save")
            s.sendline("logo")
            s.sendline("y")
        print("CREATED SPANNING TREE")

    def send_ping(self, ip_dst):
        pkt = packet.Packet()
        if ip_dst in self.arp_table:
            mac_dst = self.arp_table[ip_dst]
        else:
            return
        pkt.add_protocol(ethernet.ethernet(ethertype=0x800,dst=mac_dst,\
                                                           src=self.hw_addr))

        pkt.add_protocol(ipv4.ipv4(dst= ip_dst, src=self.ip_addr,proto=1))
        pkt.add_protocol(icmp.icmp(type_= 8, code=0, csum=0))#Not sure about echo
        print("Ping packet sent")
        self._flood_packet(pkt)

    def map_hosts(self,time=2):
        with open("ipList.txt", "r") as f:
            lines = f.readlines()
        
        shuffle(lines)
        for line in lines:
            line = line.strip()
            print("Sending ARP to " + line)
            self._handle_arp_rq(line)
            hub.sleep(1)
