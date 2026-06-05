#!/usr/bin/env python3
"""
topology.py - Simulated IoT Network for DDoS Detection FYP
"""

from mininet.net import Mininet
from mininet.node import Controller, OVSKernelSwitch
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel, info


def build_iot_network():
    info('*** Creating Mininet network\n')
    net = Mininet(controller=Controller, switch=OVSKernelSwitch, link=TCLink)

    info('*** Adding controller\n')
    net.addController('c0')

    info('*** Adding gateway switch\n')
    s1 = net.addSwitch('s1')

    info('*** Adding cloud server\n')
    server = net.addHost('server', ip='10.0.0.1/24', mac='00:00:00:00:00:01')

    info('*** Adding 10 IoT devices\n')
    iot_devices = []
    for i in range(1, 11):
        ip_address = f'10.0.0.{9 + i}/24'
        mac_address = f'00:00:00:00:00:{10 + i:02x}'
        device = net.addHost(f'iot{i}', ip=ip_address, mac=mac_address)
        iot_devices.append(device)

    info('*** Adding 2 fog nodes\n')
    fog1 = net.addHost('fog1', ip='10.0.0.50/24', mac='00:00:00:00:00:50')
    fog2 = net.addHost('fog2', ip='10.0.0.51/24', mac='00:00:00:00:00:51')

    info('*** Adding links between devices and gateway\n')
    net.addLink(server, s1, bw=100, delay='1ms')
    for device in iot_devices:
        net.addLink(device, s1, bw=10, delay='5ms')
    net.addLink(fog1, s1, bw=50, delay='2ms')
    net.addLink(fog2, s1, bw=50, delay='2ms')

    info('*** Starting the network\n')
    net.start()

    info('*** Testing connectivity with pingAll\n')
    net.pingAll()

    info('*** Network is ready. Type "exit" to stop.\n')
    CLI(net)

    info('*** Stopping network\n')
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    build_iot_network()
