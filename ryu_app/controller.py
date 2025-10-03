from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4
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
        self.flow_stats = defaultdict(lambda: defaultdict(dict))
        self.flow_tracking_thread = hub.spawn(self._flow_monitor)
        # Define the API endpoint
        self.ai_api_url = "http://127.0.0.1:5000/analyze" # Use localhost as it's on the same machine
        self.logger.info("✅ AI Controller Initialized. Will connect to API at %s", self.ai_api_url)

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
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
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
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port
        out_port = self.mac_to_port[dpid].get(eth.dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]
        if out_port != ofproto.OFPP_FLOOD:
            # We now match on IP addresses to create more meaningful flows for the AI
            if pkt.get_protocol(ipv4.ipv4):
                ip = pkt.get_protocol(ipv4.ipv4)
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                        ipv4_src=ip.src, ipv4_dst=ip.dst)
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def _flow_monitor(self):
        hub.sleep(5)
        while True:
            self.logger.info("--- Polling Cycle Started ---")
            for dp in list(self.datapaths.values()):
                self._request_stats(dp)
            hub.sleep(5)
            self.logger.info("🔎 Analyzing collected flow data...")
            self._analyze_flows() # This will call your existing _analyze_flows method
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
            if stat.priority != 1 or 'ipv4_src' not in stat.match:
                continue
            flow_key = (
                stat.match['ipv4_src'],
                stat.match['ipv4_dst'],
                stat.match.get('tcp_dst') or stat.match.get('udp_dst', 0)
            )
            current_time = time.time()
            if flow_key not in self.flow_stats[dpid]:
                self.flow_stats[dpid][flow_key] = {
                    'start_time': current_time, 'last_update': current_time,
                    'prev_packet_count': 0, 'prev_byte_count': 0,
                    'fwd_packets': 0, 'fwd_bytes': 0,
                }
            flow_data = self.flow_stats[dpid][flow_key]
            packet_delta = stat.packet_count - flow_data['prev_packet_count']
            byte_delta = stat.byte_count - flow_data['prev_byte_count']
            flow_data['fwd_packets'] += packet_delta
            flow_data['fwd_bytes'] += byte_delta
            flow_data['last_update'] = current_time
            flow_data['prev_packet_count'] = stat.packet_count
            flow_data['prev_byte_count'] = stat.byte_count
            self.logger.debug(f"Updated flow {flow_key}: {packet_delta} new packets, {byte_delta} new bytes.")

    def _analyze_flows(self):
        flow_batch_for_ai = []
        flow_keys_in_batch = []
        
        current_time = time.time()
        for dpid, flows in list(self.flow_stats.items()):
            for flow_key, data in list(flows.items()):
                if current_time - data['last_update'] > 15:
                    self.logger.info(f"🗑️  Pruning inactive flow: {flow_key}")
                    del self.flow_stats[dpid][flow_key]
                    continue

                duration = data['last_update'] - data['start_time']
                if duration == 0: duration = 1e-6
                
                packets_per_second = data['fwd_packets'] / duration

                feature_dict = {
                    "Destination Port": flow_key[2],
                    "Flow Duration": duration, "Total Fwd Packets": data['fwd_packets'],
                    "Total Backward Packets": 0, "Total Length of Fwd Packets": data['fwd_bytes'],
                    "Total Length of Bwd Packets": 0,
                    "Packet Length Mean": data['fwd_bytes'] / data['fwd_packets'] if data['fwd_packets'] > 0 else 0,
                    "Flow Packets/s": packets_per_second,
                    " Fwd Packet Length Mean": data['fwd_bytes'] / data['fwd_packets'] if data['fwd_packets'] > 0 else 0,
                    " Bwd Packet Length Mean": 0,
                }
                feature_dict[" Flow Duration"] = feature_dict["Flow Duration"]
                feature_dict[" Total Fwd Packets"] = feature_dict["Total Fwd Packets"]
                feature_dict[" Total Backward Packets"] = feature_dict["Total Backward Packets"]
                feature_dict["Total Length of Fwd Packets"] = feature_dict["Total Length of Fwd Packets"]
                feature_dict[" Total Length of Bwd Packets"] = feature_dict["Total Length of Bwd Packets"]
                feature_dict[" Flow Packets/s"] = feature_dict["Flow Packets/s"]
                flow_batch_for_ai.append(feature_dict)
                flow_keys_in_batch.append(flow_key)

        if not flow_batch_for_ai:
            self.logger.info("No active flows to analyze.")
            return

        self.logger.info(f"🧠 Sending {len(flow_batch_for_ai)} flows to AI API for analysis...")
        
        try:
            # --- API CALL ---
            response = requests.post(self.ai_api_url, json={'flows': flow_batch_for_ai}, timeout=5)
            response.raise_for_status() # Raise an exception for bad status codes
            results = response.json().get('results', [])
        except requests.exceptions.RequestException as e:
            self.logger.error("❌ Failed to connect to AI API server: %s", e)
            return

        for flow_key, result in zip(flow_keys_in_batch, results):
            src_ip, dst_ip, dst_port = flow_key
            log_msg = f"AI RESULT for flow {src_ip} -> {dst_ip}:{dst_port} is [{result}]"
            
            if result == "DDOS": self.logger.critical(f"🚨🚨🚨 {log_msg} 🚨🚨🚨")
            elif result == "CONGESTION": self.logger.warning(f"🚦 {log_msg}")
            elif result == "NORMAL": self.logger.info(f"✅ {log_msg}")
            else: self.logger.error(f"❌ {log_msg}")