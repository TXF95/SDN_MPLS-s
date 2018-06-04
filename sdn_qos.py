#-*- coding:utf-8 -*-

import logging
import random
import networkx as nx
import json
import re

from ryu.lib import ip
from ryu.lib import hub
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import ether_types
from ryu.lib.packet import tcp

from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.ofproto import inet

from ryu.topology import event, switches
from ryu.topology.api import get_all_switch, get_all_link, get_all_host

from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from collections import defaultdict, OrderedDict
from webob import Response


WAIT_PERIOD = 5
MAX_INFINITE = 100
MAX_LABEL_VALUE = 100

class SdnMplsApp(app_manager.RyuApp) :
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
	_NAME = 'SDN_MPLS_APP'
	_CONTEXTS = {
		"wsgi": WSGIApplication
	}

	def __init__(self, *args, **kwargs) :
		super(SdnMplsApp, self).__init__(*args, **kwargs)

		self.name = 'SDN_MPLS_APP'
		self.app = self

		# switch dp2ports table <switch, set(port)>
		self.switch_dp2ports_table = {}

		self.switch_dict = {}

		# link dp2port table
		self.link_dp2port_table = {}

		# host ip2mac table
		self.host_ip2mac_table = {}

		# host ip2port table
		self.host_ip2port_table = {}

		# topology graph
		self.topo_graph = nx.Graph()

		# optimized path
		self.spf_path_set = []

		# mpls ldp table <in_label, out_label>
		self.forward_label_table = {}

		self.taken_label_set = set()

		# topology discovery thread
		self.discovery_thread = hub.spawn(self._topo_discover)

		self.peer_pair_set = set()
		
		self.datapaths = defaultdict(lambda: None)
		self.src_links = defaultdict(lambda: defaultdict(lambda: None))
		self.qos_ip_bw_list = []
		self.bandwidth = {}
		self.json_bandwidth = []
		self.ip_to_port = {}
		self.mac_to_port = {}
		self.ip_to_mac = {}
		self.mac_to_dpid = {}  # {mac:(dpid,port)}
		self.check_ip_dpid = defaultdict(list)
		
		wsgi = kwargs['wsgi']
		wsgi.register(GetBandwidthRESTAPI, {'qos_ip_bw_list': self.qos_ip_bw_list, 'datapaths': self.datapaths, 'bandwidth': self.bandwidth, 'json_bandwidth': self.json_bandwidth})
		wsgi.register(SetBandwidthController, {'qos_ip_bw_list': self.qos_ip_bw_list, 'datapaths': self.datapaths})


	def add_flow(self, dp, match, actions, priority, idle_timeout = 0, hard_timeout = 0) :
		inst = [dp.ofproto_parser.OFPInstructionActions(
					dp.ofproto.OFPIT_APPLY_ACTIONS, actions)]

		mod = dp.ofproto_parser.OFPFlowMod(
			datapath = dp, cookie = 0, cookie_mask = 0, 
			table_id = 0, command = dp.ofproto.OFPFC_ADD, 
			idle_timeout = idle_timeout, hard_timeout = hard_timeout,
			priority = priority, buffer_id = 0xffffffff,
			out_port = dp.ofproto.OFPP_ANY, out_group = dp.ofproto.OFPG_ANY,
			flags = 0, match = match, instructions = inst)

		dp.send_msg(mod)

		
	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev) :
		dp = ev.msg.datapath
		ofproto = dp.ofproto
		parser = dp.ofproto_parser
		msg = ev.msg

		self.logger.info("[INFO] Switch [%s] Connected.", dp.id)

		# install table-miss flow entry
		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
						ofproto.OFPCML_NO_BUFFER)]

		self.add_flow(dp, match, actions, 0)

		
	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		if ev.msg.msg_len < ev.msg.total_len:
			self.logger.debug("packet truncated: only %s of %s bytes",
				ev.msg.msg_len, ev.msg.total_len)
		
		msg = ev.msg
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		in_port = msg.match['in_port']

		pkt = packet.Packet(msg.data)
		etherFrame = pkt.get_protocol(ethernet.ethernet)

		eth = pkt.get_protocols(ethernet.ethernet)[0]
		pkt_arp = pkt.get_protocol(arp.arp)
		pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
		pkt_tcp = pkt.get_protocol(tcp.tcp)

		if etherFrame.ethertype == ether_types.ETH_TYPE_LLDP:
			return

		dst = eth.dst
		src = eth.src
		dpid = datapath.id
		
		self.mac_to_port.setdefault(dpid, {})
		self.mac_to_port[dpid][src] = in_port

		
		# arp handle
		if pkt_arp and pkt_arp.opcode == arp.ARP_REQUEST:
			if pkt_arp.src_ip not in self.ip_to_mac:
				self.ip_to_mac[pkt_arp.src_ip] = src
				self.mac_to_dpid[src] = (dpid, in_port)
				self.ip_to_port[pkt_arp.src_ip] = (dpid, in_port)

			if pkt_arp.dst_ip in self.ip_to_mac:
				self.logger.info("[PACKET] ARP packet_in.")
				self.handle_arpre(datapath=datapath, port=in_port, 
						  src_mac=self.ip_to_mac[pkt_arp.dst_ip], 
						  dst_mac=src,src_ip=pkt_arp.dst_ip, dst_ip=pkt_arp.src_ip)
			else:
			# to avoid flood when the dst ip not in the network
				if datapath.id not in self.check_ip_dpid[pkt_arp.dst_ip]:
					self.check_ip_dpid[pkt_arp.dst_ip].append(datapath.id)
					out_port = ofproto.OFPP_FLOOD
					actions = [parser.OFPActionOutput(out_port)]
					data = None
					
					if msg.buffer_id == ofproto.OFP_NO_BUFFER:
						data = msg.data
						out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
									in_port=in_port, actions=actions, data=data)
						datapath.send_msg(out)
			return

		elif pkt_arp and pkt_arp.opcode == arp.ARP_REPLY:
			if pkt_arp.src_ip not in self.ip_to_mac:
				self.ip_to_mac[pkt_arp.src_ip] = src
				self.mac_to_dpid[src] = (dpid, in_port)
				self.ip_to_port[pkt_arp.src_ip] = (dpid, in_port)
				dst_mac = self.ip_to_mac[pkt_arp.dst_ip]
				(dst_dpid, dst_port) = self.mac_to_dpid[dst_mac]
				self.logger.info("[PACKET] ARP packet_in.")
				self.handle_arpre(datapath=self.datapaths[dst_dpid], port=dst_port, src_mac=src, dst_mac=dst_mac,
						src_ip=pkt_arp.src_ip, dst_ip=pkt_arp.dst_ip)
			return
		
		#if etherFrame.ethertype == ether.ETH_TYPE_IP:
		#	self.logger.info("[PACKET] IPv4 packet_in.")
		#	self.handle_ping_ipv4(datapath, pkt, etherFrame, in_port)
		#	return
		
		if pkt_ipv4 and (self.ip_to_port.get(pkt_ipv4.dst)) and (self.ip_to_port.get(pkt_ipv4.src)):
			(src_dpid, src_port) = self.ip_to_port[pkt_ipv4.src]  # src dpid and port
			(dst_dpid, dst_port) = self.ip_to_port[pkt_ipv4.dst]  # dst dpid and port
			self.install_path(src_dpid=src_dpid, dst_dpid=dst_dpid, src_port=src_port, dst_port=dst_port,
					  ev=ev, src=src, dst=dst, pkt_ipv4=pkt_ipv4, pkt_tcp=pkt_tcp)

		
	def send_pkt(self, datapath, port, pkt):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		pkt.serialize()
		data = pkt.data
		actions = [parser.OFPActionOutput(port=port)]
 		out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, 
					  in_port=ofproto.OFPP_CONTROLLER,
					  actions=actions, data=data)
		datapath.send_msg(out)	
		
	def handle_arpre(self, datapath, port, src_mac, dst_mac, src_ip, dst_ip):
		pkt = packet.Packet()
		pkt.add_protocol(ethernet.ethernet(ethertype=0x0806, dst=dst_mac, src=src_mac))
		pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=src_mac, src_ip=src_ip, dst_mac=dst_mac, dst_ip=dst_ip))
		self.send_pkt(datapath, port, pkt)
	
	
	def judge(self, pkt_ipv4, pkt_tcp, info_list):
		src_ip = pkt_ipv4.src
		dst_ip = pkt_ipv4.dst
		src_port = pkt_tcp.src_port
		dst_port = pkt_tcp.dst_port
		
		if dict.get('src_ip')!= None and dict.get('dst_ip') == None and \
			dict.get('src_port') == None and dict.get('dst_port') == None:
			if dict['src_ip'] == src_ip:
				return dict
			elif dict['src_ip'] == dst_ip:
				return dict
				
		elif dict.get('src_ip')!= None and dict.get('dst_ip') != None and \
			dict.get('src_port') == None and dict.get('dst_port') == None:
			if dict['src_ip'] == src_ip and dict['dst_ip'] == dst_ip:
				return dict
			elif dict['src_ip'] == dst_ip and dict['dst_ip'] == src_ip:
				return dict
			
		elif dict.get('src_ip')!= None and dict.get('dst_ip') != None and \
			dict.get('src_port') != None and dict.get('dst_port') != None:
			if dict['src_ip'] == src_ip and dict['dst_ip'] == dst_ip and \
				int(dict['src_port']) == src_port and int(dict['dst_port']) == dst_port:
					return dict
			elif dict['src_ip'] == dst_ip and dict['dst_ip'] == src_ip and \
				int(dict['src_port']) == dst_port and int(dict['dst_port']) == src_port:
					return dict
				
		return False
		
		
	# obtain topology period.
	def _topo_discover(self) :
		while True:
			self.obtain_topology(None)
			hub.sleep(WAIT_PERIOD)\
			
	events = [event.EventSwitchEnter,
			event.EventSwitchLeave,
			event.EventPortAdd,
			event.EventPortDelete,
			event.EventPortModify,
			event.EventLinkAdd,
			event.EventLinkDelete]

	@set_ev_cls(events)
	def obtain_topology(self, ev) :
		self.switches = get_all_switch(self.app)
		self.links = get_all_link(self.app)
		self.hosts = get_all_host(self.app)

		# handle switches
		for switch in self.switches :
			#print "[INFO]", switch
			dpid = switch.dp.id
			self.switch_dict[dpid] = switch.dp
			self.switch_dp2ports_table.setdefault(dpid, set())
			for port in switch.ports:
				self.switch_dp2ports_table[dpid].add(port)

		# handle links
		for link in self.links :
			#print "[INFO]", link
			src_port = link.src
			dst_port = link.dst
			self.link_dp2port_table[(src_port.dpid, dst_port.dpid)] = (src_port, dst_port)

		# handle hosts
		for host in self.hosts :
			#print "[INFO]", host
			host_ip = host.ipv4
			host_mac = host.mac
			host_port = host.port
			if len(host_ip) == 0 :
				pass
			else:
				self.host_ip2mac_table[host_ip[0]] = host_mac
				self.host_ip2port_table[host_ip[0]] = host_port

		self.process_topo_graph_and_paths()

	def process_topo_graph_and_paths(self) :
		self.topo_graph.clear()
		link_dp_set = self.link_dp2port_table.keys()
		for src in self.switches :
			for dst in self.switches :
				src_id = src.dp.id
				dst_id = dst.dp.id
				if (src_id, dst_id) in link_dp_set :
					self.topo_graph.add_edge(src_id, dst_id)	
		#get shorstest path
		self.spf_path_set = nx.all_pairs_shortest_path(self.topo_graph)

	# set mpls path for ping host-pair
	def handle_ping_ipv4(self, datapath, pkt, etherFrame, in_port) :
		ip_packet = pkt.get_protocol(ipv4.ipv4)
		pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
		pkt_tcp = pkt.get_protocol(tcp.tcp)
		ip_src_ip = ip_packet.src
		ip_dst_ip = ip_packet.dst

		if (ip_src_ip, ip_dst_ip) in self.peer_pair_set :
			return

		if ip_src_ip not in self.host_ip2port_table.keys() :
			self.logger.info("Host from src %s is not acceptable." % ip_src_ip)
			return
		elif ip_dst_ip not in self.host_ip2port_table.keys() :
			self.logger.info("Host to dst %s is not acceptable." % ip_dst_ip)
			return
		else :
			ip_src_dp = self.host_ip2port_table[ip_src_ip].dpid
			ip_src_port = self.host_ip2port_table[ip_src_ip].port_no
			ip_dst_dp = self.host_ip2port_table[ip_dst_ip].dpid
			ip_dst_port = self.host_ip2port_table[ip_dst_ip].port_no

		print "[PING ACTION] begin host ip = ", ip_src_ip
		print "[PING ACTION] end host ip = ", ip_dst_ip
		print "[PING ACTION] begin switch id = ", ip_src_dp
		print "[PING ACTION] end switch id = ", ip_dst_dp

		if ip_src_dp == ip_dst_dp :
			forward_path = [ip_src_dp]
		else :
			forward_path = self.spf_path_set[ip_src_dp][ip_dst_dp]
		print "SPF Forward Path = ", forward_path

		self.installMplsPath(forward_path, ip_src_ip, ip_dst_ip, ip_src_dp, ip_dst_dp, ip_src_port, ip_dst_port, pkt_ipv4, pkt_tcp)

		#if ip_src_dp == ip_dst_dp :
			#backward_path = [ip_src_dp]
		#else :
		#	backward_path = self.spf_path_set[ip_dst_dp][ip_src_dp]
		#print "SPF Backward Path = ", backward_path

		#self.installMplsPath(backward_path, ip_src_ip, ip_dst_ip, ip_dst_dp, ip_src_dp, ip_dst_port, ip_src_port, pkt_ipv4)

		self.peer_pair_set.add((ip_src_ip, ip_dst_ip))


	def get_avaliable_label(self) :
		label = random.randint(1, MAX_LABEL_VALUE)
		if label in self.taken_label_set :
			self.get_avaliable_label()
		else :
			self.taken_label_set.add(label)
			return label

		
	# install MPLS path
	def installMplsPath(self, path, src_ip, dst_ip, begin_dp, end_dp, begin_in_port, end_out_port, pkt_ipv4, pkt_tcp) :
		
		path_size = len(path)
		
		if path_size <= 0 :
			return
		elif path_size == 1 :
			if begin_dp != end_dp :
				return
			if pkt_tcp:
				self.logger.info("src_port : %s", pkt_tcp.src_port)
				self.logger.info("dst_port : %s", pkt_tcp.dst_port)
				self.logger.info("qos_ip_bw_list: %s", self.qos_ip_bw_list)
				qos_info_dict = self.judge(pkt_ipv4, pkt_tcp, self.qos_ip_bw_list)
				self.logger.info("qos_info_dict: %s", qos_info_dict)
				
				if qos_info_dict:
					queue_id = 1
				else:
					queue_id = 0
					
			else:
				qos_info_dict = self.judge(pkt_ipv4, pkt_tcp, self.qos_ip_bw_list)
				self.logger.info("qos_info_dict: %s", qos_info_dict)
				if qos_info_dict:
					queue_id = 1
				else:
					queue_id = 0
	
			dpid = path[0]
			dp = self.switch_dict[dpid]
			match = dp.ofproto_parser.OFPMatch()
			match.set_dl_type(ether.ETH_TYPE_IP)
			match.set_in_port(begin_in_port)
			actions = [dp.ofproto_parser.OFPActionSetQueue(queue_id=queue_id),
				   dp.ofproto_parser.OFPActionOutput(end_out_port, 0)]
			self.add_flow(dp, match, actions)
			return
		else :
			# mpls operation
			if path[0] != begin_dp :
				return
			if path[path_size - 1] != end_dp :
				return

			# first switch -- push mpls label
			i = 0
			j = 1
			dpid = path[i]
			dpid_next = path[j]
			(prev_port_out, next_port_in) = self.link_dp2port_table[(dpid, dpid_next)]
			
			if pkt_tcp:
				self.logger.info("src_port : %s", pkt_tcp.src_port)
				self.logger.info("dst_port : %s", pkt_tcp.dst_port)
				self.logger.info("qos_ip_bw_list: %s", self.qos_ip_bw_list)
				qos_info_dict = self.judge(pkt_ipv4, pkt_tcp, self.qos_ip_bw_list)
				self.logger.info("qos_info_dict: %s", qos_info_dict)
				
				if qos_info_dict:
					queue_id = 1
				else:
					queue_id = 0
					
			else:
				qos_info_dict = self.judge(pkt_ipv4, pkt_tcp, self.qos_ip_bw_list)
				self.logger.info("qos_info_dict: %s", qos_info_dict)
				if qos_info_dict:
					queue_id = 1
				else:
					queue_id = 0
			
			dp = self.switch_dict[dpid]
			
			match = dp.ofproto_parser.OFPMatch()
			match.set_dl_type(ether.ETH_TYPE_IP)
			match.set_in_port(begin_in_port)
			match.set_ipv4_dst(ip.ipv4_to_int(dst_ip))
			
			begin_label = self.get_avaliable_label()
			field = dp.ofproto_parser.OFPMatchField.make(dp.ofproto.OXM_OF_MPLS_LABEL, int(begin_label))

			actions = [dp.ofproto_parser.OFPActionSetQueue(queue_id=queue_id),
				   dp.ofproto_parser.OFPActionPushMpls(ether.ETH_TYPE_MPLS),
				   dp.ofproto_parser.OFPActionSetField(field),
				   dp.ofproto_parser.OFPActionOutput(prev_port_out.port_no, 0)]
			
			print "Push Label Number = %s." % begin_label
			self.add_flow(dp, match, actions, 0xff)

			# mediate switch -- switch mpls label
			i = i + 1
			j = j + 1
			tmp_label = begin_label
			while path[i] != end_dp :
				dpid = path[i]
				dpid_next = path[j]
				(prev_port_out, next_port_in) = self.link_dp2port_table[(dpid, dpid_next)]
				
				if pkt_tcp:
					self.logger.info("src_port : %s", pkt_tcp.src_port)
					self.logger.info("dst_port : %s", pkt_tcp.dst_port)
					self.logger.info("qos_ip_bw_list: %s", self.qos_ip_bw_list)
					qos_info_dict = self.judge(pkt_ipv4, pkt_tcp, self.qos_ip_bw_list)
					self.logger.info("qos_info_dict: %s", qos_info_dict)
				
					if qos_info_dict:
						queue_id = 1
					else:
						queue_id = 0
					
				else:
					qos_info_dict = self.judge(pkt_ipv4, pkt_tcp, self.qos_ip_bw_list)
					self.logger.info("qos_info_dict: %s", qos_info_dict)
					if qos_info_dict:
						queue_id = 1
					else:
						queue_id = 0
				
				dp = self.switch_dict[dpid]
				match = dp.ofproto_parser.OFPMatch()
				match.set_dl_type(ether.ETH_TYPE_MPLS)
				match.set_mpls_label(tmp_label)

				flabel = self.get_avaliable_label()
				field = dp.ofproto_parser.OFPMatchField.make(dp.ofproto.OXM_OF_MPLS_LABEL, int(flabel))
				self.forward_label_table[tmp_label] = flabel

				actions = [dp.ofproto_parser.OFPActionSetQueue(queue_id=queue_id),
					   dp.ofproto_parser.OFPActionPopMpls(ether.ETH_TYPE_IP),
					   dp.ofproto_parser.OFPActionPushMpls(ether.ETH_TYPE_MPLS),
					   dp.ofproto_parser.OFPActionSetField(field),
					   dp.ofproto_parser.OFPActionOutput(prev_port_out.port_no, 0)]
				print "Swap Label Number = %s -> %s." % (tmp_label, flabel)
				self.add_flow(dp, match, actions, 0xff)

				tmp_label = flabel
				i = i + 1
				j = j + 1

			# last switch -- pop mpls label
			if pkt_tcp:
				self.logger.info("src_port : %s", pkt_tcp.src_port)
				self.logger.info("dst_port : %s", pkt_tcp.dst_port)
				self.logger.info("qos_ip_bw_list: %s", self.qos_ip_bw_list)
				qos_info_dict = self.judge(pkt_ipv4, pkt_tcp, self.qos_ip_bw_list)
				self.logger.info("qos_info_dict: %s", qos_info_dict)
				
				if qos_info_dict:
					queue_id = 1
				else:
					queue_id = 0
					
			else:
				qos_info_dict = self.judge(pkt_ipv4, pkt_tcp, self.qos_ip_bw_list)
				self.logger.info("qos_info_dict: %s", qos_info_dict)
				if qos_info_dict:
					queue_id = 1
				else:
					queue_id = 0
			
			dpid = end_dp
			dp = self.switch_dict[dpid]
			match = dp.ofproto_parser.OFPMatch()
			match.set_dl_type(ether.ETH_TYPE_MPLS)
			match.set_mpls_label(tmp_label)
			actions = [dp.ofproto_parser.OFPActionSetQueue(queue_id=queue_id),
				   dp.ofproto_parser.OFPActionPopMpls(ether.ETH_TYPE_IP),
				   dp.ofproto_parser.OFPActionOutput(end_out_port, 0)]
			print "Pop Label Number = %s." % tmp_label
			self.add_flow(dp, match, actions, 0xff)
			
			
	@set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
	def _get_bandwidth(self, ev):
		for key in self.src_links:
			tmp = self.src_links[key]
			for key1 in tmp:
				sw_src = key1[0]
				sw_dst = key1[1]
				src_port = tmp[key1][0]
				dst_port = tmp[key1][1]
				key_speed = (sw_src, sw_dst, src_port, dst_port)
				value_speed = self.network_monitor.get_port_speed(sw_src, src_port)
				self.bandwidth[key_speed] = value_speed
		#self.logger.info("port_speed : %s", str(self.bandwidth))
		self._json_bandwidth(self.bandwidth)
		return self.bandwidth

	def _json_bandwidth(self, dist):
		del self.json_bandwidth[:]
		for key in dist:
			_bandwidth = OrderedDict()
			_bandwidth['src_sw'] = key[0]
			_bandwidth['dst_sw'] = key[1]
			_bandwidth['src_port'] = key[2]
			_bandwidth['dst_port'] = key[3]
			_bandwidth['port_speed'] = dist.get(key)[0]
			_bandwidth['time'] = dist.get(key)[1]
			#self.logger.info("dist.gey(key): %s", str(dist.get(key)))
			#self.json_bandwidth.append(_bandwidth)
			#self.logger.info("json_bandwidth : %s", str(self.json_bandwidth))
			self.json_bandwidth.append(_bandwidth)
		return self.json_bandwidth
	

class SetBandwidthController(ControllerBase):
	def __init__(self, req, link, data, **config):
		super(SetBandwidthController, self).__init__(req, link, data, **config)
		self.re_ip = ur'^(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])$'
		self.qos_ip_bw_list = data['qos_ip_bw_list']
		self.datapaths = data['datapaths']
		
		self.logger = logging.getLogger('my_logger')

	def delete_flow(self, src_ip=None, src_port=None, dst_ip=None, dst_port=None):
		for datapath_id in self.datapaths:
			datapath = self.datapaths[datapath_id]
			ofproto = datapath.ofproto
			parser = datapath.ofproto_parser
			if src_ip and src_port and dst_ip and dst_port:
				match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip, tcp_src=src_port,
							ipv4_dst=dst_ip, tcp_dst=dst_port, ip_proto=6)
			
			elif src_ip and dst_ip:
				match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip, ip_proto=6)
			
			elif src_ip:
				match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip, ip_proto=6)
				
			elif dst_ip:
				match = parser.OFPMatch(eth_type=0x0800, ipv4_dst=dst_ip, ip_proto=6)
				
				# OFPFlowMod:The controller sends this message to modify the flow table.
				mod = parser.OFPFlowMod(datapath=datapath, match=match, command=ofproto.OFPFC_DELETE,
							out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)
				datapath.send_msg(mod)

	
	# curl http://127.0.0.1:8080/get/qos/limit/all
	# curl http://127.0.0.1:8080/get/qos/limit/10.0.0.1
	@route('getqoslimit', '/get/qos/limit/all', methods=['GET'])
	def get_bw_limit_all(self, req, **kwargs):
		body = json.dumps(self.qos_ip_bw_list)
		return Response(content_type='application/json', body=body)

	
	#  curl -d '{"src_ip":10.0.0.100,"src_port":8000,"dst_ip":20.0.0.101,"dst_port":9000}' http://127.0.0.1:8080/get/qos/limit
	@route('getbandwidth_two', '/get/qos/limit', methods=['POST'])
	def get_bw_limit_one(self, req, **kwargs):
		try:
			get_qos_dict = req.json if req.body else {}
		except ValueError:
			return Response(status=400, body="failure")
		
		for qos_ip_bw_dict in self.qos_ip_bw_list:
			if get_qos_dict.get('src_ip') and get_qos_dict.get('dst_ip') and get_qos_dict.get('src_port') and get_qos_dict.get('dst_port'):
				if get_qos_dict['src_ip'] == qos_ip_bw_dict.get('src_ip') and get_qos_dict['dst_ip'] == qos_ip_bw_dict.get('dst_ip') \
					and get_qos_dict['src_port'] == qos_ip_bw_dict.get('src_port') and get_qos_dict['dst_port'] == qos_ip_bw_dict.get('dst_port'):
					body = json.dumps(qos_ip_bw_dict)
					
			elif get_qos_dict.get('src_ip') and get_qos_dict.get('dst_ip'):
				if get_qos_dict['src_ip'] == qos_ip_bw_dict.get('src_ip') and get_qos_dict['dst_ip'] == qos_ip_bw_dict.get('dst_ip'):
					body = json.dumps(qos_ip_bw_dict)
			
			elif get_qos_dict.get('src_ip'):
				if get_qos_dict['src_ip'] == qos_ip_bw_dict.get('src_ip'):
					body = json.dumps(qos_ip_bw_dict)
		return Response(content_type='application/json', body=body)


	# curl -d '{"src_ip":10.0.0.100,"src_port":8000,"dst_ip":20.0.0.101,"dst_port":9000,"bw":5}' http://127.0.0.1:8080/set/qoslimit
	# curl -d '[{"10.0.0.1":10},{"10.0.0.2":5}]' http://127.0.0.1:8080/set/qos/limit
	@route('setbandwidth', '/set/qos/limit', methods=['POST'])
	def set_bw_limit(self, req, **kwargs):
		try:
			set_qos_bw = req.json if req.body else {}
			self.logger.info("ip_bw: %s", set_qos_bw)
		except ValueError:
			return Response(status=400)
		
		if set_qos_bw.get('src_ip') and set_qos_bw.get('src_port') and set_qos_bw.get('dst_ip') and set_qos_bw.get('dst_port'):
			if re.match(self.re_ip, set_qos_bw['src_ip']) and re.match(self.re_ip, set_qos_bw['dst_ip']) and set_qos_bw not in self.qos_ip_bw_list:
				self.qos_ip_bw_list.append(set_qos_bw)
				self.delete_flow(set_qos_bw['src_ip'], int(set_qos_bw['src_port']), set_qos_bw['dst_ip'], int(set_qos_bw['dst_port']))
				self.delete_flow(set_qos_bw['dst_ip'], int(set_qos_bw['dst_port']), set_qos_bw['src_ip'], int(set_qos_bw['src_port']))
		
		elif set_qos_bw.get('src_ip') and set_qos_bw.get('dst_ip'):
			if re.match(self.re_ip, set_qos_bw['src_ip']) and re.match(self.re_ip, set_qos_bw['dst_ip']) and set_qos_bw not in self.qos_ip_bw_list:
				self.qos_ip_bw_list.append(set_qos_bw)
				self.delete_flow(src_ip=set_qos_bw['src_ip'], dst_ip=set_qos_bw['dst_ip'])
				self.delete_flow(src_ip=set_qos_bw['dst_ip'], dst_ip=set_qos_bw['src_ip'])
		
		elif set_qos_bw.get('src_ip'):
			if re.match(self.re_ip, set_qos_bw['src_ip']) and set_qos_bw not in self.qos_ip_bw_list:
				self.qos_ip_bw_list.append(set_qos_bw)
				self.delete_flow(src_ip=set_qos_bw['src_ip'])
				self.delete_flow(dst_ip=set_qos_bw['src_ip'])
		return Response(status=200, body='success')

	
	@route('modifybandwidth', '/modify/qos/limit', methods=['POST'])
	def modify_bw_limit(self, req, **kwargs):
		try:
			modify_bw_info = req.json if req.body else {}
		except ValueError:
			return Response(status=400)
		
		if modify_bw_info.get('src_ip') and modify_bw_info.get('src_port') and modify_bw_info.get('dst_ip') and modify_bw_info.get('dst_port'):
			if re.match(self.re_ip, modify_bw_info['src_ip']) and re.match(self.re_ip, modify_bw_info['dst_ip']):
				for qos_ip_bw_dict in self.qos_ip_bw_list:
					if modify_bw_info['src_ip'] == qos_ip_bw_dict.get('src_ip') and modify_bw_info['dst_ip'] == qos_ip_bw_dict.get('dst_ip') \
					and modify_bw_info['src_port'] == qos_ip_bw_dict.get('src_port') and modify_bw_info['dst_port'] == qos_ip_bw_dict.get('dst_port'):
						self.qos_ip_bw_list.remove(qos_ip_bw_dict)
						self.qos_ip_bw_list.append(modify_bw_info)
						self.delete_flow(qos_ip_bw_dict['src_ip'], int(qos_ip_bw_dict['src_port']),
								 qos_ip_bw_dict['dst_ip'], int(qos_ip_bw_dict['dst_port']))
						self.delete_flow(qos_ip_bw_dict['dst_ip'], int(qos_ip_bw_dict['dst_port']),
								 qos_ip_bw_dict['src_ip'], int(qos_ip_bw_dict['src_port']))
				body = json.dumps(self.qos_ip_bw_list)
				
		elif modify_bw_info.get('src_ip') and modify_bw_info.get('dst_ip'):
			if re.match(self.re_ip, modify_bw_info['src_ip']) and re.match(self.re_ip, modify_bw_info['dst_ip']):
				for qos_ip_bw_dict in self.qos_ip_bw_list:
					if modify_bw_info['src_ip'] == qos_ip_bw_dict.get('src_ip') and modify_bw_info['dst_ip'] == qos_ip_bw_dict.get('dst_ip'):
						self.qos_ip_bw_list.remove(qos_ip_bw_dict)
						self.qos_ip_bw_list.append(modify_bw_info)
						self.delete_flow(src_ip=modify_bw_info['src_ip'], dst_ip=modify_bw_info['dst_ip'])
						self.delete_flow(src_ip=modify_bw_info['dst_ip'], dst_ip=modify_bw_info['src_ip'])
				body = json.dumps(self.qos_ip_bw_list)
		
		elif modify_bw_info.get('src_ip'):
			if re.match(self.re_ip, modify_bw_info['src_ip']):
				for qos_ip_bw_dict in self.qos_ip_bw_list:
					if modify_bw_info['src_ip'] == qos_ip_bw_dict.get('src_ip'):
						self.qos_ip_bw_list.remove(qos_ip_bw_dict)
						self.qos_ip_bw_list.append(modify_bw_info)
						self.delete_flow(src_ip=modify_bw_info['src_ip'])
						self.delete_flow(dst_ip=modify_bw_info['src_ip'])
				body = json.dumps(self.qos_ip_bw_list)
		
		return Response(content_type='application/json', body=body)



	#curl - d '{"src_ip":"10.0.0.100", "src_port":"20.0.0.101", "dst_port":"51092"}' http://127.0.0.1:8080/delete/qos/limit
	@route('delbandwidth_one', '/delete/qos/limit', methods=['POST'])
	def del_bw_limit_one(self, req, **kwargs):
		try:
			del_qos = req.json if req.body else {}
		except ValueError:
			return Response(status=400, body="failure")
		
		if del_qos.get('src_ip') and del_qos.get('dst_ip') and del_qos.get('src_port') and del_qos.get('dst_port'):
			for qos_ip_bw_dict in self.qos_ip_bw_list:
				if del_qos['src_ip'] == qos_ip_bw_dict.get('src_ip') and del_qos['dst_ip'] == qos_ip_bw_dict.get('dst_ip') \
				and del_qos['src_port'] == qos_ip_bw_dict.get('src_port') and del_qos['dst_port'] == qos_ip_bw_dict.get('dst_port'):
					self.qos_ip_bw_list.remove(qos_ip_bw_dict)
					self.delete_flow(del_qos['src_ip'], int(del_qos['src_port']), del_qos['dst_ip'], int(del_qos['dst_port']))
					self.delete_flow(del_qos['dst_ip'], int(del_qos['dst_port']), del_qos['src_ip'], int(del_qos['src_port']))
			body = json.dumps(self.qos_ip_bw_list)
				
		elif del_qos.get('src_ip') and del_qos.get('dst_ip'):
			for qos_ip_bw_dict in self.qos_ip_bw_list:
				if del_qos['src_ip'] == qos_ip_bw_dict.get('src_ip') and del_qos['dst_ip'] == qos_ip_bw_dict.get('dst_ip'):
					self.qos_ip_bw_list.remove(qos_ip_bw_dict)
					self.delete_flow(src_ip=del_qos['src_ip'], dst_ip=del_qos['dst_ip'])
					self.delete_flow(src_ip=del_qos['dst_ip'], dst_ip=del_qos['src_ip'])
			body = json.dumps(self.qos_ip_bw_list)
					
		elif del_qos.get('src_ip'):
			for qos_ip_bw_dict in self.qos_ip_bw_list:
				if del_qos['src_ip'] == qos_ip_bw_dict.get('src_ip'):
					self.qos_ip_bw_list.remove(qos_ip_bw_dict)
					self.delete_flow(src_ip=del_qos['src_ip'])
					self.delete_flow(dst_ip=del_qos['src_ip'])
			body = json.dumps(self.qos_ip_bw_list)

		return Response(content_type='application/json', body=body)


	@route('delbandwidth_two', '/delete/qos/limit/all', methods=['GET'])
	def del_bw_limit_all(self, req, **kwargs):
		for qos_ip_bw_dict in self.qos_ip_bw_list:
			if qos_ip_bw_dict.get('src_ip') and qos_ip_bw_dict.get('dst_ip') and qos_ip_bw_dict.get('src_port') and qos_ip_bw_dict.get('dst_port'):
				self.delete_flow(qos_ip_bw_dict['src_ip'], int(qos_ip_bw_dict['src_port']),
						 qos_ip_bw_dict['dst_ip'], int(qos_ip_bw_dict['dst_port']))
				self.delete_flow(qos_ip_bw_dict['dst_ip'], int(qos_ip_bw_dict['dst_port']),
						 qos_ip_bw_dict['src_ip'], int(qos_ip_bw_dict['src_port']))
		
			elif qos_ip_bw_dict.get('src_ip') and qos_ip_bw_dict.get('dst_ip'):
				self.delete_flow(src_ip=qos_ip_bw_dict['src_ip'], dst_ip=qos_ip_bw_dict['dst_ip'])
				self.delete_flow(src_ip=qos_ip_bw_dict['dst_ip'], dst_ip=qos_ip_bw_dict['src_ip'])
			
			elif qos_ip_bw_dict.get('src_ip'):
					self.delete_flow(src_ip=qos_ip_bw_dict['src_ip'])
					self.delete_flow(dst_ip=qos_ip_bw_dict['src_ip'])
		del self.qos_ip_bw_list[:]
		body = json.dumps(self.qos_ip_bw_list)
		return Response(content_type='application/json', body=body)


class GetBandwidthRESTAPI(ControllerBase):
	def __init__(self, req, link, data, **config):
		super(GetBandwidthRESTAPI, self).__init__(req, link, data, **config)
		self.json_bandwidth = data['json_bandwidth']
		self.bandwidth = data['bandwidth']

	def _get_bandwidth_2switch(self, sw_src=None, sw_dst=None, src_port=None, dst_port=None):
		bandwidth_2switch = {}
		if sw_src is None or sw_dst is None or src_port is None or dst_port is None:
			return
		in_port_speed = self.bandwidth.get((sw_src, sw_dst, src_port, dst_port))[0]
		out_port_speed = self.bandwidth.get((sw_dst, sw_src, dst_port, src_port))[0]
		time = self.bandwidth.get((sw_dst, sw_src, dst_port, src_port))[1]

		if in_port_speed is not None and out_port_speed is not None:
			bandwidth_2switch['in_port_speed'] = in_port_speed
			bandwidth_2switch['out_port_speed'] = out_port_speed
			bandwidth_2switch['time'] = time
			
			return json.dumps(bandwidth_2switch)
		
		else:
			return


	@route('getbandwidth', '/get/bandwidth/all', methods=['GET'])
	def get_all_speed(self, req, **kwargs):
		body = json.dumps(self.json_bandwidth)
		return Response(content_type='application/json', body=body)

	# curl -d '{"src_sw": 2, "src_port": 1, "dst_sw": 1, "dst_port": 2}' http://127.0.0.1:8080/get/linkspeed
	@route('getlinkspeed', '/get/linkspeed', methods=['POST'])
	def get_link_speed(self, req, **kwargs):
		try:
			link_state = req.json if req.body else{}

		except ValueError:
			return Response(status=400, body="failure")
		
		sw_src = link_state['src_sw']
		sw_dst = link_state['dst_sw']
		src_port = link_state['src_port']
		dst_port = link_state['dst_port']
		body = self._get_bandwidth_2switch(sw_src, sw_dst, src_port, dst_port)
		return Response(content_type='application/json', body=body)