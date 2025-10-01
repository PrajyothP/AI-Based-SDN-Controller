# osken_app/controller.py

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from os_ken.controller.handler import set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet, ethernet, ether_types, ipv4, tcp, udp # Added ipv4, tcp, udp
from os_ken.lib import hub

from ai_pipeline import AIPipeline
# from .llm_handler import LLMHandler

ANALYSIS_INTERVAL = 10  # seconds

class SimpleSwitch13(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    # --- THIS IS THE CRITICAL CHANGE ---
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
            return # ignore lldp packet
        
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # --- MODIFIED SECTION ---
        # Install a flow to avoid packet_in next time.
        # We handle IP packets differently to ensure L3/L4 stats are recorded.
        if out_port != ofproto.OFPP_FLOOD:
            match_fields = {'in_port': in_port, 'eth_dst': dst, 'eth_src': src}

            # If this is an IP packet, add L3 and L4 details to the match
            ip = pkt.get_protocol(ipv4.ipv4)
            if ip:
                match_fields['eth_type'] = ether_types.ETH_TYPE_IP
                match_fields['ipv4_src'] = ip.src
                match_fields['ipv4_dst'] = ip.dst

                # If TCP or UDP, add port numbers for even more specific stats
                tcp_pkt = pkt.get_protocol(tcp.tcp)
                if tcp_pkt:
                    match_fields['ip_proto'] = ip.proto
                    match_fields['tcp_src'] = tcp_pkt.src_port
                    match_fields['tcp_dst'] = tcp_pkt.dst_port
                
                udp_pkt = pkt.get_protocol(udp.udp)
                if udp_pkt:
                    match_fields['ip_proto'] = ip.proto
                    match_fields['udp_src'] = udp_pkt.src_port
                    match_fields['udp_dst'] = udp_pkt.dst_port
            
            match = parser.OFPMatch(**match_fields)
            # Use a timeout so idle flows are removed
            self.add_flow(datapath, 1, match, actions, idle_timeout=15, hard_timeout=60)
        # --- END MODIFIED SECTION ---

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

# --- Your AiSdnController class remains the same from the previous step ---
class AiSdnController(SimpleSwitch13):
    _CONTEXTS = {}

    def __init__(self, *args, **kwargs):
        super(AiSdnController, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.flow_aggregator = {} 
        self.analysis_buffer = []
        self.ai_pipeline = AIPipeline(model_dir='models/')
        self.monitor_thread = hub.spawn(self._monitor)
        self.logger.info(f"🤖 AI-SDN Controller started. Analysis interval: {ANALYSIS_INTERVAL}s.")

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(datapath.id, None)

    def _monitor(self):
        while True:
            hub.sleep(ANALYSIS_INTERVAL)
            for dp in self.datapaths.values():
                self._request_stats(dp)
            
            self.logger.info(f"--- Running analysis on {len(self.analysis_buffer)} flows collected in the last {ANALYSIS_INTERVAL}s ---")
            if self.analysis_buffer:
                results = self.ai_pipeline.analyze_flow_batch(self.analysis_buffer)
                
                for flow_data, result in zip(self.analysis_buffer, results):
                    if result != "NORMAL":
                        self.logger.warning(f"Flow {flow_data['flow_id']} flagged as {result}")

            self.analysis_buffer = []
            self.flow_aggregator = {}

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        for stat in body:
            if stat.priority != 1 or 'ipv4_src' not in stat.match or 'ipv4_dst' not in stat.match:
                continue

            ip_src = stat.match['ipv4_src']
            ip_dst = stat.match['ipv4_dst']
            flow_key = tuple(sorted((ip_src, ip_dst)))

            if flow_key not in self.flow_aggregator:
                self.flow_aggregator[flow_key] = {}
            if ip_src < ip_dst:
                direction = 'fwd'
            else:
                direction = 'bwd'
            self.flow_aggregator[flow_key][direction] = stat

            if 'fwd' in self.flow_aggregator[flow_key] and 'bwd' in self.flow_aggregator[flow_key]:
                fwd_stat = self.flow_aggregator[flow_key]['fwd']
                bwd_stat = self.flow_aggregator[flow_key]['bwd']
                duration = max(fwd_stat.duration_sec, bwd_stat.duration_sec)
                if duration == 0: continue
                total_packets = fwd_stat.packet_count + bwd_stat.packet_count
                if total_packets == 0: continue
                feature_dict = {
                    "flow_id": f"{ip_src}:{fwd_stat.match.get('tcp_src',fwd_stat.match.get('udp_src',0))}-{ip_dst}:{fwd_stat.match.get('tcp_dst',fwd_stat.match.get('udp_dst',0))}",
                    "Destination Port": fwd_stat.match.get('tcp_dst') or fwd_stat.match.get('udp_dst') or 0,
                    "Flow Duration": duration,
                    "Total Fwd Packets": fwd_stat.packet_count,
                    "Total Backward Packets": bwd_stat.packet_count,
                    "Total Length of Fwd Packets": fwd_stat.byte_count,
                    "Total Length of Bwd Packets": bwd_stat.byte_count,
                    "Packet Length Mean": (fwd_stat.byte_count + bwd_stat.byte_count) / total_packets,
                    " Flow Duration": duration * 1_000_000,
                    " Total Fwd Packets": fwd_stat.packet_count,
                    " Total Backward Packets": bwd_stat.packet_count,
                    "Total Length of Fwd Packets": fwd_stat.byte_count,
                    " Total Length of Bwd Packets": bwd_stat.byte_count,
                    " Fwd Packet Length Mean": fwd_stat.byte_count / fwd_stat.packet_count if fwd_stat.packet_count > 0 else 0,
                    " Bwd Packet Length Mean": bwd_stat.byte_count / bwd_stat.packet_count if bwd_stat.packet_count > 0 else 0,
                    " Flow Packets/s": total_packets / duration
                }
                self.analysis_buffer.append(feature_dict)
                self.flow_aggregator.pop(flow_key, None)