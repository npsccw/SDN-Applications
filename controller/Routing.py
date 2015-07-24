#Required Ryu modules
from ryu.base import app_manager
from ryu.controller import mac_to_port, ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.controller.dpset import DPSet
from ryu.ofproto import ofproto_v1_0, inet, ether
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp
from ryu.lib import hub

#Supporting Python modules
import struct
import hashlib
from multiprocessing import Pipe, Process
from utils import *

class SimpleSwitch(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

	_CONTEXTS = {
    		'dpset': DPSet,
		}

	def __init__(self, *args, **kwargs):
	        super(SimpleSwitch, self).__init__(*args, **kwargs)
        	self.mac_to_port = {} #MAC address => port
		self.ip_to_port = {} #IP address => port
		self.dpid_to_port = {} #Datapath ID => port
		self.DPSet = kwargs['dpset']
		self.dpids = {} #Datapath ID => Datapath Object
		
		
	def _handle_ARP_packet(self, datapath, in_port, dst, dl_type, data, actions):
		#add flow for ARP packets
		ofproto = datapath.ofproto
		match = datapath.ofproto_parser.OFPMatch(dl_type=dl_type, in_port=in_port, 
			dl_dst=haddr_to_bin(dst))
        	mod = datapath.ofproto_parser.OFPFlowMod(datapath=datapath, match=match,\
			 cookie=0,command=ofproto.OFPFC_ADD, idle_timeout=600,\
			 hard_timeout=3600,priority=ofproto.OFP_DEFAULT_PRIORITY,\
			 flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        	datapath.send_msg(mod)
		
                #Pass along orginal packet
                out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=0xffffffff,\
			 in_port=in_port,actions=actions, data=data)
                datapath.send_msg(out)

    	def _handle_IP_packet(self, out, datapath, in_port, dst, actions, dl_type, src, data):
		#add flow for IP packets	
		ofproto = datapath.ofproto
		dpid = datapath.id

    		res = dot_to_dec(dst)
    		src_res = dot_to_dec(src)
	
		match = datapath.ofproto_parser.OFPMatch(dl_type=dl_type, in_port=in_port, 
			nw_src=src_res, nw_dst=res)
		self.add_flow(datapath, in_port, actions, dl_type)
		
		#Pass along original packet
		out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,\
                                         buffer_id=0xffffffff, in_port=in_port,\
                                                actions=actions, data=data)
                datapath.send_msg(out)

	
	#catch all flow. I don't think this ever actually gets executed, but you never know.
    	def add_flow(self, datapath, in_port, actions, dl_type):
		ofproto = datapath.ofproto
		match = datapath.ofproto_parser.OFPMatch(dl_type=dl_type, in_port=in_port)

		mod = datapath.ofproto_parser.OFPFlowMod(
	 		datapath=datapath, match=match, cookie=0,
			command=ofproto.OFPFC_ADD, idle_timeout=600, hard_timeout=3600,
	      		priority=ofproto.OFP_DEFAULT_PRIORITY,
	      		flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
		datapath.send_msg(mod)


	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		msg = ev.msg
	        datapath = msg.datapath
	        ofproto = datapath.ofproto

	        pkt = packet.Packet(msg.data)
	        eth = pkt.get_protocol(ethernet.ethernet)
		ip = pkt.get_protocol(ipv4.ipv4)
        	pkt_tcp = pkt.get_protocol(tcp.tcp)

		dstMAC = eth.dst
	        srcMAC = eth.src
		
		if ip:
		    dstIP = ip.dst
		    srcIP = ip.src
		else: 
		    dstIP = 0xFFFFFFFF
		    srcIP = 0xFFFFFFFF
		
	        dpid = datapath.id

	        self.mac_to_port.setdefault(dpid, {})
		self.ip_to_port.setdefault(dpid, {})

		# learn a Source mac address to avoid FLOOD next time.
		# sdn ports range from 1-24, controller port is port 6####
		if msg.in_port < 25 and srcMAC not in self.mac_to_port[dpid]:
			self.mac_to_port[dpid][srcMAC] = msg.in_port
		if msg.in_port < 25 and srcIP != 0xFFFFFFFF\
			 and srcIP not in self.ip_to_port[dpid]:
				self.ip_to_port[dpid][srcIP] = msg.in_port

		#determine what to do with each packet based on current learned locations or flood		
		http_pkt = False
		if (pkt_tcp and (pkt_tcp.src_port == 80)):
			out_port = ofproto.OFPP_CONTROLLER
			http_pkt = True
		elif dstMAC in self.mac_to_port[dpid]:
			out_port = self.mac_to_port[dpid][dstMAC]
		elif dstIP in self.ip_to_port[dpid]:
			out_port = self.ip_to_port[dpid][dstIP]
		else:		
			out_port = ofproto.OFPP_FLOOD
	
        	actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

		#Send HTTP Packets to Controller
		if http_pkt:
    			res = dot_to_dec(dstIP)
    			src_res = dot_to_dec(srcIP)

			#match is based on ethernet type, incoming port and network dest (ip address)
			match = datapath.ofproto_parser.OFPMatch(dl_type=0x800, in_port=msg.in_port, 
			nw_src=src_res, nw_dst=res)
			mod = datapath.ofproto_parser.OFPFlowMod(
	 			datapath=datapath, match=match, cookie=0,
				command=ofproto.OFPFC_ADD, idle_timeout=600, hard_timeout=3600,
	      			priority=ofproto.OFP_DEFAULT_PRIORITY,
	      			flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
			datapath.send_msg(mod)

		#Flood ARP Packets
		elif dstMAC == "ff:ff:ff:ff:ff:ff" and eth.ethertype != 0x002c:
			self._handle_ARP_packet(datapath, msg.in_port, dstMAC, eth.ethertype, msg.data, actions)	

		#Drop non-IP and non-ARP packets
		elif eth.ethertype != 0x800 and eth.ethertype != 0x806:
             		actions=None
             		self.add_flow(datapath, msg.in_port, actions=actions, dl_type=eth.ethertype)

		#IP Packet
        	elif eth.ethertype == 0x800:
			self._handle_IP_packet(out_port, datapath, msg.in_port, dstIP, 
					actions, eth.ethertype, srcIP, msg.data)

        	elif eth.ethertype == 0x806:
			if msg.in_port == out_port:
				out_port = ofproto.OFPP_FLOOD
				
				#here I assign the action that the flow should take
        			actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

				print "in port equals out port for IP traffic 0x806"
				self._handle_ARP_packet(datapath, msg.in_port, dstMAC, eth.ethertype,\
						msg.data,actions) 
			else:
		    		self._handle_ARP_packet(datapath, msg.in_port, dstMAC, eth.ethertype,\
					        msg.data,actions) 
		
