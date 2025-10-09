from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, icmp, tcp, udp
from ryu.lib import hub

from collections import defaultdict
import requests
import json
import time

class AIController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(AIController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.logger.info("Initializing AI SDN Controller...")
        self.flow_stats = defaultdict(dict)
        self.flow_tracking_thread = hub.spawn(self._flow_monitor)
        self.ai_api_url = "http://127.0.0.1:5000/analyze"
        self.logger.info("✅ AI Controller Initialized. Will connect to API at %s", self.ai_api_url)

    # FINAL: This key function correctly identifies the service port.
    def _get_canonical_flow_key(self, src_ip, dst_ip, proto, src_port, dst_port):
        """
        Creates a canonical key that groups traffic between two IPs to a specific 
        service port, making it bidirectional. It correctly identifies the service
        port vs. the client's ephemeral port.
        """
        # Prioritize the well-known port (0-1023) as the service port
        if 0 <= dst_port <= 1023:
            service_port = dst_port
        elif 0 <= src_port <= 1023:
            service_port = src_port
        else:
            # If both are high-level ports, default to the destination port.
            # This handles peer-to-peer or non-standard server ports.
            service_port = dst_port
        
        # Order IPs to ensure bidirectionality
        if src_ip < dst_ip:
            return (src_ip, dst_ip, proto, service_port)
        else:
            return (dst_ip, src_ip, proto, service_port)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.info('✅ Switch %d connected.', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.warning('❌ Switch %d disconnected.', datapath.id)
                del self.datapaths[datapath.id]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.logger.info("Configuring switch %d...", datapath.id)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info("👍 Switch %d configured with table-miss rule.", datapath.id)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod_args = {'datapath': datapath, 'priority': priority, 'match': match, 'instructions': inst}
        if buffer_id:
            mod_args['buffer_id'] = buffer_id
        mod = parser.OFPFlowMod(**mod_args)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        
        if eth.ethertype == ether_types.ETH_TYPE_LLDP: return
            
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port
        out_port = self.mac_to_port[dpid].get(eth.dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match_args = {'eth_type': eth.ethertype, 'in_port': in_port, 'eth_src': eth.src, 'eth_dst': eth.dst}
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if ip_pkt:
                match_args.update({'ipv4_src': ip_pkt.src, 'ipv4_dst': ip_pkt.dst, 'ip_proto': ip_pkt.proto})
                if ip_pkt.proto == 6: # TCP
                    tcp_pkt = pkt.get_protocol(tcp.tcp)
                    match_args.update({'tcp_src': tcp_pkt.src_port, 'tcp_dst': tcp_pkt.dst_port})
                elif ip_pkt.proto == 17: # UDP
                    udp_pkt = pkt.get_protocol(udp.udp)
                    match_args.update({'udp_src': udp_pkt.src_port, 'udp_dst': udp_pkt.dst_port})
            
            match = parser.OFPMatch(**match_args)
            self.add_flow(datapath, 1, match, actions, msg.buffer_id)
            
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def _flow_monitor(self):
        hub.sleep(10)
        while True:
            self.logger.info("--- Polling Cycle Started ---")
            for dp in list(self.datapaths.values()):
                self._request_stats(dp)
            hub.sleep(5)
            self.logger.info("🔎 Analyzing collected flow data...")
            self._analyze_flows()
            hub.sleep(10)

    def _request_stats(self, datapath):
        self.logger.info('📡 Requesting flow stats from switch %d...', datapath.id)
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        self.logger.info("Received flow stats from switch %d.", dpid)
        for stat in body:
            if stat.priority != 1 or 'ipv4_src' not in stat.match: continue

            src_ip = stat.match['ipv4_src']
            dst_ip = stat.match['ipv4_dst']
            proto = stat.match['ip_proto']
            src_port = stat.match.get('tcp_src') or stat.match.get('udp_src', 0)
            dst_port = stat.match.get('tcp_dst') or stat.match.get('udp_dst', 0)
            
            # CHANGED: Use the robust service-port-aware key function
            flow_key = self._get_canonical_flow_key(src_ip, dst_ip, proto, src_port, dst_port)
            
            current_time = time.time()
            if flow_key not in self.flow_stats:
                self.flow_stats[flow_key] = {
                    'start_time': current_time,
                    'last_update': current_time,
                    'fwd_packets': 0, 'fwd_bytes': 0,
                    'bwd_packets': 0, 'bwd_bytes': 0,
                    'forward_src_ip': flow_key[0] # The first IP in the key is "forward"
                }
            
            flow_data = self.flow_stats[flow_key]
            
            packet_delta = stat.packet_count - flow_data.get(f'dpid_{dpid}_{stat.cookie}_pkts', 0)
            byte_delta = stat.byte_count - flow_data.get(f'dpid_{dpid}_{stat.cookie}_bytes', 0)

            if src_ip == flow_data['forward_src_ip']:
                flow_data['fwd_packets'] += packet_delta
                flow_data['fwd_bytes'] += byte_delta
            else:
                flow_data['bwd_packets'] += packet_delta
                flow_data['bwd_bytes'] += byte_delta
            
            flow_data['last_update'] = current_time
            flow_data[f'dpid_{dpid}_{stat.cookie}_pkts'] = stat.packet_count
            flow_data[f'dpid_{dpid}_{stat.cookie}_bytes'] = stat.byte_count

    def _analyze_flows(self):
        flow_batch_for_ai, flow_keys_in_batch = [], []
        current_time = time.time()

        for flow_key, data in list(self.flow_stats.items()):
            if current_time - data['last_update'] > 20:
                self.logger.info(f"🗑️  Pruning inactive flow: {flow_key}")
                del self.flow_stats[flow_key]
                continue

            duration = data['last_update'] - data['start_time']
            
            total_packets = data['fwd_packets'] + data['bwd_packets']
            total_bytes = data['fwd_bytes'] + data['bwd_bytes']
            
            # The service port is always the 4th element in our key
            srv_port = flow_key[3]

            feature_dict = {
                "Destination Port": srv_port,
                "Flow Duration": duration,
                "Total Fwd Packets": data['fwd_packets'],
                "Total Backward Packets": data['bwd_packets'],
                "Total Length of Fwd Packets": data['fwd_bytes'],
                "Total Length of Bwd Packets": data['bwd_bytes'],
                "Fwd Packet Length Mean": data['fwd_bytes'] / data['fwd_packets'] if data['fwd_packets'] > 0 else 0,
                "Bwd Packet Length Mean": data['bwd_bytes'] / data['bwd_packets'] if data['bwd_packets'] > 0 else 0,
                "Packet Length Mean": total_bytes / total_packets if total_packets > 0 else 0,
                "Flow Packets/s": total_packets / duration if duration > 0 else 0,
            }
            flow_batch_for_ai.append(feature_dict)
            flow_keys_in_batch.append(flow_key)

        if not flow_batch_for_ai:
            self.logger.info("No flows to analyze in this cycle.")
            return

        self.logger.info(f"🧠 Sending {len(flow_batch_for_ai)} flows to AI API for analysis...")
        try:
            response = requests.post(self.ai_api_url, json={'flows': flow_batch_for_ai}, timeout=5)
            response.raise_for_status()
            results = response.json().get('results', [])
        except requests.exceptions.RequestException as e:
            self.logger.error("❌ Failed to connect to AI API server: %s", e)
            return

        for flow_key, result_data in zip(flow_keys_in_batch, results):
            ip1, ip2, proto, srv_port = flow_key
            
            label = result_data.get("label", "UNKNOWN")
            confidence = result_data.get("confidence", 0.0)
            
            log_msg = (
                f"AI RESULT for flow ({ip1} <-> {ip2} on srv port {srv_port}, proto {proto}) "
                f"is [{label}] with confidence {confidence:.2%}"
            )
            
            if label == "DDOS":
                self.logger.critical(f"🚨🚨🚨 {log_msg} 🚨🚨🚨")
            elif label == "CONGESTION":
                self.logger.warning(f"🚦 {log_msg}")
            else:
                self.logger.info(f"✅ {log_msg}")