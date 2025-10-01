#!/usr/bin/python

import time
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info

class AI_SDN_Topo(Topo):
    """Custom topology for the AI-SDN Project."""
    def build(self):
        # Adding switches
        s1 = self.addSwitch('s1', dpid='0000000000000001')
        s2 = self.addSwitch('s2', dpid='0000000000000002')
        s3 = self.addSwitch('s3', dpid='0000000000000003')
        s4 = self.addSwitch('s4', dpid='0000000000000004')

        # Adding hosts
        h1 = self.addHost('h1', ip='10.0.1.1/24')
        h2 = self.addHost('h2', ip='10.0.1.2/24')
        server = self.addHost('server', ip='10.0.2.1/24')
        attacker1 = self.addHost('attacker1', ip='10.0.3.1/24')
        attacker2 = self.addHost('attacker2', ip='10.0.3.2/24')

        # Creating links
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(server, s2)
        self.addLink(attacker1, s3)
        self.addLink(attacker2, s3)
        self.addLink(s1, s4)
        self.addLink(s2, s4)
        self.addLink(s3, s4)

def run_congestion_test():
    """Creates the network and runs the congestion test."""
    topo = AI_SDN_Topo()
    # Use RemoteController since your OS-Ken controller is running separately
    net = Mininet(topo=topo, controller=RemoteController('c0', ip='127.0.0.1'))

    info("*** Starting network\n")
    net.start()

    # Get host objects
    server = net.get('server')
    h1 = net.get('h1')
    h2 = net.get('h2')

    TEST_DURATION = 60
    LOG_FILE = "congestion_ping_log.txt"

    info(f"*** Starting iperf server on {server.name}\n")
    # The '.cmd()' method runs a command on the host
    server.cmd(f'iperf -s > /dev/null &')

    info(f"*** Starting ping from {h2.name} to {server.name}\n")
    h2.cmd(f'ping {server.IP()} > {LOG_FILE} &')

    info(f"*** Starting iperf clients from {h1.name} and {h2.name}\n")
    h1.cmd(f'iperf -c {server.IP()} -t {TEST_DURATION} -b 10M > /dev/null &')
    h2.cmd(f'iperf -c {server.IP()} -t {TEST_DURATION} -b 10M > /dev/null &')

    info(f"--- Test is running for {TEST_DURATION} seconds. ---\n")
    time.sleep(TEST_DURATION)

    info("*** Test finished. Cleaning up.\n")
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run_congestion_test()

# This exposes the topology to the 'mn' command if you ever need it
topos = {'aisdntopo': (lambda: AI_SDN_Topo())}