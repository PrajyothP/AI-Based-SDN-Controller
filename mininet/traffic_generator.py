from mininet.log import info
import time

class TrafficGenerator:
    """A class to manage traffic generation in the Mininet simulation."""

    def __init__(self, net):
        self.net = net
        self.http_server = None
        self.iperf_server = None
        self.background_clients = []
        self.attack_pids = {}

    def start_background_traffic(self):
        """Starts long-lived, low-intensity background traffic."""
        info('*** Starting continuous background traffic...\n')
        
        # 1. Long-lived file transfer (TCP)
        server = self.net.get('h18')
        client = self.net.get('h2')
        info(f'--- Starting long-lived iperf server on {server.name}\n')
        self.iperf_server = server.popen('iperf -s -p 5001')
        time.sleep(1)
        info(f'--- Starting long-lived iperf client from {client.name} to {server.name} (2Mbps)\n')
        # This will run for a very long time, simulating a file transfer
        client.cmd(f'iperf -c {server.IP()} -p 5001 -b 2M -t 3600 &')
        
        # 2. Periodic web requests
        self.http_server = self.net.get('h1')
        web_clients = [self.net.get('h5'), self.net.get('h8')]
        info(f'--- Starting simple HTTP server on {self.http_server.name}\n')
        self.http_server.cmd('python3 -m http.server 80 &')
        time.sleep(1)
        for client in web_clients:
            info(f'--- Starting periodic web client on {client.name}\n')
            # This command will fetch the webpage every 20 seconds
            client.cmd(f'while true; do wget -q -O - http://{self.http_server.IP()}/; sleep 20; done &')

    def start_congestion_flood(self):
        """Generates a high-volume UDP flood to cause network congestion."""
        info('*** Starting high-volume congestion flood...\n')
        server = self.net.get('h17') # A host far away
        client = self.net.get('h3')  # A host on the first switch
        
        # Start a UDP iperf server on the destination
        server.cmd('iperf -s -u -p 5002 &')
        time.sleep(1)
        
        info(f'--- {client.name} flooding {server.name} with 100Mbps UDP traffic\n')
        # This attempts to send 100Mbps over a 20Mbps link, causing severe congestion
        pid = client.popen(f'iperf -c {server.IP()} -p 5002 -u -b 100M -t 60').pid
        self.attack_pids[f'congestion_{client.name}'] = pid


    def start_ddos_syn_flood(self):
        """Launches a direct (non-spoofed) TCP SYN flood DDoS attack."""
        info('*** STAGE 1 ATTACK: Launching TCP SYN Flood DDoS Attack...\n')
        victim = self.net.get('h1')
        attackers = [self.net.get('h4'), self.net.get('h7'), self.net.get('h10')]

        for attacker in attackers:
            info(f'--- Starting SYN flood from {attacker.name} -> {victim.name}\n')
            # --flood sends packets as fast as possible. No --rand-source means the real IP is used.
            pid = attacker.popen(f'hping3 -S -p 80 --flood {victim.IP()}').pid
            self.attack_pids[f'syn_{attacker.name}'] = pid
            
    def start_ddos_udp_flood(self):
        """Launches a different type of DDoS attack: a high-packet-rate UDP flood."""
        info('*** STAGE 2 ATTACK: Launching UDP Flood DDoS Attack...\n')
        victim = self.net.get('h1')
        # Use different hosts for the second wave of the attack
        attackers = [self.net.get('h13'), self.net.get('h16')]
        
        # The victim needs to be listening on the UDP port
        victim.cmd('iperf -s -u -p 5003 &')
        time.sleep(1)
        
        for attacker in attackers:
            info(f'--- Starting UDP flood from {attacker.name} -> {victim.name}\n')
            # -b 10M: Limit bandwidth to avoid simple congestion detection
            # -l 64: Use small packets
            # By sending 10Mbps of 64-byte packets, we generate a very high packet-per-second rate
            pid = attacker.popen(f'iperf -c {victim.IP()} -p 5003 -u -b 10M -l 64 -t 120').pid
            self.attack_pids[f'udp_{attacker.name}'] = pid

    def stop_all_traffic(self):
        """Stops all running traffic generation processes."""
        info('*** Stopping all traffic generators...\n')
        for host in self.net.hosts:
            host.cmd('killall hping3')
            host.cmd('killall iperf')
            host.cmd('killall wget')
            host.cmd('killall python3') # Stops the simple http server
