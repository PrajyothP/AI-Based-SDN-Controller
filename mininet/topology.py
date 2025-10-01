#!/usr/bin/env python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf # Import Intf
from mininet.topo import Topo

def myNetwork():
    # Use RemoteController since our controller is running outside Mininet
    info('*** Adding controller\n')
    # Use the VM's actual IP address
    c0 = RemoteController('c0', ip='192.168.64.4', port=6633)

    info('*** Creating a network\n')
    net = Mininet(controller=c0, link=TCLink) # Use TCLink for traffic shaping later if needed

    info('*** Adding hosts and switch\n')
    h1 = net.addHost('h1', ip='10.0.0.1/24') # Assign static IPs
    h2 = net.addHost('h2', ip='10.0.0.2/24')
    s1 = net.addSwitch('s1')

    info('*** Creating links\n')
    net.addLink(h1, s1)
    net.addLink(h2, s1)

    info('*** Starting network\n')
    net.start()
    
    # This is the crucial part that was missing.
    # It disables the default IP on the switch's control interface...
    s1.cmd('ifconfig s1-eth1 0')
    # ...and makes sure the switch can communicate with the controller.
    s1.cmd('ovs-vsctl set-controller s1 tcp:192.168.64.4:6633')


    info('*** Running CLI\n')
    CLI(net)

    info('*** Stopping network\n')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    myNetwork()