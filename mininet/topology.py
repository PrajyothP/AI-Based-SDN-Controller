#!/usr/bin/env python

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import sys
import time
from mininet.topo import Topo

# Import the new classes
from traffic_generator import TrafficGenerator
from stats_logger import StatsLogger

class MyTopo(Topo):
    def build(self):
        switches = []
        for i in range(1, 7):
            s = self.addSwitch(f's{i}', cls=OVSKernelSwitch, protocols='OpenFlow13')
            switches.append(s)

        hosts = []
        for i in range(1, 19):
            h = self.addHost(f'h{i}', ip=f'10.0.0.{i}/24', 
                             mac=f'00:00:00:00:00:{i:02x}')
            hosts.append(h)

        info('*** Adding host-to-switch links (50Mbps)\n')
        for i in range(6):
            for j in range(3):
                self.addLink(hosts[i*3 + j], switches[i], bw=50)

        info('*** Adding switch-to-switch links (20Mbps bottleneck)\n')
        for i in range(5):
            self.addLink(switches[i], switches[i+1], bw=20)

def startNetwork(controller_ip):
    info('*** Creating network\n')
    topo = MyTopo()
    c0 = RemoteController('c0', ip=controller_ip, port=6653)
    net = Mininet(topo=topo, link=TCLink, controller=c0)

    info('*** Starting network\n')
    net.start()

    # Initialize the logger and traffic generator
    stats_logger = StatsLogger(net)
    traffic_generator = TrafficGenerator(net)

    info('*** Waiting for controller to establish links...\n')
    time.sleep(10)

    # --- Start the simulation sequence ---
    stats_logger.start()
    traffic_generator.start_background_traffic()

    info('\n*** PHASE 1: Network running with normal background traffic (30s)...\n')
    time.sleep(30)

    info('\n*** PHASE 2: Generating congestion event (60s)...\n')
    traffic_generator.start_congestion_flood()
    time.sleep(60)

    info('\n*** PHASE 3: Launching Stage 1 DDoS Attack (TCP SYN Flood) (90s)...\n')
    traffic_generator.start_ddos_syn_flood()
    time.sleep(90) # Give the controller time to detect and mitigate

    info('\n*** PHASE 4: Launching Stage 2 DDoS Attack (UDP Flood) (120s)...\n')
    traffic_generator.start_ddos_udp_flood()
    
    info('\n*** Simulation running. Open CLI for manual commands.\n')
    CLI(net)

    # --- Cleanup ---
    info('*** Stopping network and all processes\n')
    stats_logger.stop()
    traffic_generator.stop_all_traffic()
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    ctrl_ip = '127.0.0.1'
    if len(sys.argv) > 1:
        ctrl_ip = sys.argv[1]
    
    startNetwork(controller_ip=ctrl_ip)
