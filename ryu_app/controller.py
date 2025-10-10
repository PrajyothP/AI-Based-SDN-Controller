from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4
from ryu.lib import hub

from collections import defaultdict
import requests
import time

class AIController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(AIController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.logger.info("Initializing AI-Driven SDN Controller Application...")
        self.flow_stats = {} 
        self.flow_tracking_thread = hub.spawn(self._flow_monitor)
        self.ai_api_url = "http://127.0.0.1:5000/analyze"
        self.meter_id_counter = 1
        self.logger.info("AI SDN Controller initialized successfully. API endpoint is configured at: %s", self.ai_api_url)

    def _apply_llm_rule(self, rule):
        action = rule.get('action')
        details = rule.get('details')
        if not action or not details:
            self.logger.error("Failed to apply mitigation rule: The received rule object from the AI service is malformed. It is missing the 'action' or 'details' key.")
            return

        self.logger.critical(f"Applying new network mitigation policy received from AI service. Action: '{action}', Details: {details}")

        if action == 'BLOCK_IP':
            self._install_block_flow(details)
        elif action in ['RATE_LIMIT_LOW', 'RATE_LIMIT_HIGH', 'REROUTE_AND_RATE_LIMIT', 'AGGRESSIVE_DROP']:
            self._install_metered_flow(details)
        else:
            self.logger.warning(f"Received an unknown or unsupported action type '{action}' from the AI service. The rule will be ignored.")

    def _install_block_flow(self, details):
        src_ip = details.get('src_ip')
        if not src_ip:
            self.logger.error("Failed to install BLOCK_IP rule: The 'src_ip' was not specified in the rule details.")
            return

        priority = details.get('priority', 40000)
        idle_timeout = details.get('idle_timeout', 60)
        
        self.logger.critical(f"Installing BLOCK rule on all switches for source IP '{src_ip}'. Priority: {priority}, Idle Timeout: {idle_timeout}s.")
        
        match_args = {'eth_type': ether_types.ETH_TYPE_IP, 'ipv4_src': src_ip}
        if 'dst_ip' in details:
            match_args['ipv4_dst'] = details['dst_ip']

        for datapath in self.datapaths.values():
            match = datapath.ofproto_parser.OFPMatch(**match_args)
            self.add_flow(datapath, priority, match, [], idle_timeout=idle_timeout)

    def _install_metered_flow(self, details):
        rate_mbps = details.get('rate_mbps')
        src_ip = details.get('src_ip')
        if not src_ip or rate_mbps is None:
            self.logger.error("Failed to install metered flow rule: The 'src_ip' or 'rate_mbps' was not specified in the rule details.")
            return

        priority = details.get('priority', 30000)
        idle_timeout = details.get('idle_timeout', 60)
        meter_id = self.meter_id_counter
        self.meter_id_counter += 1

        self.logger.critical(f"Installing METERED flow rule on all switches for source IP '{src_ip}'. Rate limit: {rate_mbps} Mbps, Meter ID: {meter_id}, Priority: {priority}.")

        match_args = {'eth_type': ether_types.ETH_TYPE_IP, 'ipv4_src': src_ip}
        if 'dst_ip' in details:
            match_args['ipv4_dst'] = details['dst_ip']

        for datapath in self.datapaths.values():
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            
            bands = [parser.OFPMeterBandDrop(rate=int(rate_mbps * 1000), burst_size=int(rate_mbps * 100))]
            meter_mod = parser.OFPMeterMod(datapath=datapath, command=ofproto.OFPMC_ADD,
                                           flags=ofproto.OFPMF_KBPS, meter_id=meter_id, bands=bands)
            datapath.send_msg(meter_mod)

            match = parser.OFPMatch(**match_args)
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            self.add_flow(datapath, priority, match, actions, idle_timeout=idle_timeout, meter_id=meter_id)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.info('Switch connected: Datapath ID %s has established a connection with the controller.', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.warning('Switch disconnected: Datapath ID %s has lost connection with the controller.', datapath.id)
                del self.datapaths[datapath.id]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions, idle_timeout=0)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, meter_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        if meter_id is not None:
            inst.insert(0, parser.OFPInstructionMeter(meter_id=meter_id))
            
        mod_args = {
            'datapath': datapath, 'priority': priority, 'match': match, 
            'instructions': inst, 'idle_timeout': idle_timeout
        }
        if buffer_id is not None and buffer_id != ofproto.OFP_NO_BUFFER:
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
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if ip_pkt:
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                        ipv4_src=ip_pkt.src,
                                        ipv4_dst=ip_pkt.dst,
                                        ip_proto=ip_pkt.proto)
                self.add_flow(datapath, 1, match, actions, msg.buffer_id, idle_timeout=15)
            else:
                match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst)
                self.add_flow(datapath, 1, match, actions, msg.buffer_id, idle_timeout=15)

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
    
    def _flow_monitor(self):
        hub.sleep(10)
        while True:
            self.logger.info("Starting new flow statistics polling cycle.")
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(5)
            self._cleanup_stale_flows()
            self._analyze_flows()
            hub.sleep(10)

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        for stat in body:
            if stat.priority != 1 or 'ipv4_src' not in stat.match or 'ip_proto' not in stat.match:
                continue
            
            ip_src = stat.match['ipv4_src']
            ip_dst = stat.match['ipv4_dst']
            port_src = stat.match.get('tcp_src') or stat.match.get('udp_src', 0)
            port_dst = stat.match.get('tcp_dst') or stat.match.get('udp_dst', 0)

            key_part1 = tuple(sorted((ip_src, ip_dst)))
            key_part2 = (stat.match['ip_proto'], tuple(sorted((port_src, port_dst))))
            canonical_key = key_part1 + key_part2
            
            if canonical_key not in self.flow_stats:
                self.flow_stats[canonical_key] = {
                    'start_time': time.time(), 'last_update': time.time(),
                    'fwd_packets': 0, 'fwd_bytes': 0, 'bwd_packets': 0, 'bwd_bytes': 0,
                    'src_ip': ip_src, 'dst_ip': ip_dst, 'dst_port': port_dst,
                    'state': 'NEW',
                    'per_switch_stats': defaultdict(lambda: {'fwd_pkts': 0, 'fwd_bytes': 0, 'bwd_pkts': 0, 'bwd_bytes': 0})
                }
            
            flow_entry = self.flow_stats[canonical_key]
            per_switch_entry = flow_entry['per_switch_stats'][dpid]

            if ip_src == flow_entry['src_ip']:
                packet_delta = stat.packet_count - per_switch_entry['fwd_pkts']
                byte_delta = stat.byte_count - per_switch_entry['fwd_bytes']
                flow_entry['fwd_packets'] += packet_delta
                flow_entry['fwd_bytes'] += byte_delta
                per_switch_entry['fwd_pkts'] = stat.packet_count
                per_switch_entry['fwd_bytes'] = stat.byte_count
            else:
                packet_delta = stat.packet_count - per_switch_entry['bwd_pkts']
                byte_delta = stat.byte_count - per_switch_entry['bwd_bytes']
                flow_entry['bwd_packets'] += packet_delta
                flow_entry['bwd_bytes'] += byte_delta
                per_switch_entry['bwd_pkts'] = stat.packet_count
                per_switch_entry['bwd_bytes'] = stat.byte_count

            flow_entry['last_update'] = time.time()

    def _cleanup_stale_flows(self):
        current_time = time.time()
        stale_keys = [key for key, data in self.flow_stats.items() if (current_time - data['last_update']) > 20]
        if stale_keys:
            self.logger.info(f"Performing flow table cleanup. Removing {len(stale_keys)} stale flow entries from controller's internal state.")
            for key in stale_keys:
                if key in self.flow_stats:
                    del self.flow_stats[key]
    
    def _analyze_flows(self):
        if not self.flow_stats:
            self.logger.info("Flow analysis skipped: No active flows are currently being tracked by the controller.")
            return

        flow_batch_for_ai = []
        flow_keys_in_batch = []
        current_time = time.time()

        for flow_key, data in self.flow_stats.items():
            duration_sec = current_time - data['start_time']
            if duration_sec <= 0: duration_sec = 1e-6
            
            total_packets = data['fwd_packets'] + data['bwd_packets']
            total_bytes = data['fwd_bytes'] + data['bwd_bytes']
            
            feature_dict = {
                "Flow Duration": duration_sec * 1_000_000,
                "Total Fwd Packets": data['fwd_packets'],
                "Total Backward Packets": data['bwd_packets'],
                "Total Length of Fwd Packets": data['fwd_bytes'],
                "Total Length of Bwd Packets": data['bwd_bytes'],
                "Fwd Packets Length Total": data['fwd_bytes'],
                "Bwd Packets Length Total": data['bwd_bytes'],
                "Fwd Packet Length Mean": data['fwd_bytes'] / data['fwd_packets'] if data['fwd_packets'] > 0 else 0,
                "Bwd Packet Length Mean": data['bwd_bytes'] / data['bwd_packets'] if data['bwd_packets'] > 0 else 0,
                "Flow Packets/s": total_packets / duration_sec,
                "Packet Length Mean": total_bytes / total_packets if total_packets > 0 else 0,
                "Destination Port": data.get('dst_port', 0),
                "src_ip": data['src_ip'],
                "dst_ip": data['dst_ip']
            }
            flow_batch_for_ai.append(feature_dict)
            flow_keys_in_batch.append(flow_key)

        if not flow_batch_for_ai:
            return

        self.logger.info(f"Sending a batch of {len(flow_batch_for_ai)} aggregated flows to the AI analysis service.")
        
        hub.spawn(self._send_api_request, flow_batch_for_ai, flow_keys_in_batch)
    
    def _send_api_request(self, flow_batch, flow_keys):
        try:
            response = requests.post(self.ai_api_url, json={'flows': flow_batch}, timeout=30)
            response.raise_for_status()
            response_data = response.json()
            results = response_data.get('results', [])
            actionable_rules = response_data.get('actionable_rules')

            if actionable_rules and isinstance(actionable_rules, list):
                for rule in actionable_rules:
                    self._apply_llm_rule(rule)

        except requests.exceptions.RequestException as e:
            self.logger.error("Asynchronous API request to the AI service failed. Error: %s", e)
            return

        for flow_key, result_data in zip(flow_keys, results):
            if flow_key not in self.flow_stats: continue
            
            flow_entry = self.flow_stats[flow_key]
            label = result_data.get("label", "UNKNOWN")
            confidence = result_data.get("confidence", 0.0)
            current_state = flow_entry.get('state', 'NEW')
            new_state = current_state
            
            if label == "DDOS" and confidence > 0.8:
                new_state = 'DDOS'
            elif label == "CONGESTION" or (label == "DDOS" and confidence > 0.5):
                new_state = 'SUSPICIOUS'
            elif label == "NORMAL":
                new_state = 'NORMAL'

            log_msg = (
                f"AI RESULT for flow ({flow_entry['src_ip']}->{flow_entry['dst_ip']}) "
                f"is [{label}] with confidence {confidence:.2%} => resulting state={new_state}"
            )

            if new_state == 'DDOS' and current_state != 'DDOS':
                self.logger.critical(f"Flow State Transition: {current_state} -> {new_state}. A high-confidence threat was detected and a mitigation rule has been applied. Details: {log_msg}")
            elif new_state != current_state:
                self.logger.warning(f"Flow State Transition: {current_state} -> {new_state}. Details: {log_msg}")
            else:
                self.logger.info(f"Flow State Unchanged: {current_state}. Details: {log_msg}")
            
            flow_entry['state'] = new_state