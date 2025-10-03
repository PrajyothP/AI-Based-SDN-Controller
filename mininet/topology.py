#!/usr/bin/env python

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
from mininet.topo import Topo

class MyTopo(Topo):
    def build(self):
        # Create switches
        switches = []
        for i in range(1, 7):
            s = self.addSwitch(f's{i}', cls=OVSKernelSwitch, protocols='OpenFlow13')
            switches.append(s)

        # Create hosts
        hosts = []
        for i in range(1, 19):
            h = self.addHost(f'h{i}', ip=f'10.0.0.{i}/24', 
                             mac=f'00:00:00:00:00:{i:02x}', cpu=1.0/20)
            hosts.append(h)

        # Connect hosts to switches (3 per switch)
        for i in range(6):
            for j in range(3):
                self.addLink(hosts[i*3 + j], switches[i])

        # Connect switches in a linear chain
        for i in range(5):
            self.addLink(switches[i], switches[i+1])

def startNetwork():
    info('*** Creating network\n')
    topo = MyTopo()
    # Make sure this IP is your controller's IP
    c0 = RemoteController('c0', ip='192.168.64.4', port=6653)
    net = Mininet(topo=topo, link=TCLink, controller=c0)

    info('*** Starting network\n')
    net.start()

    info('*** Running CLI\n')
    CLI(net)

    info('*** Stopping network\n')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    startNetwork()
