#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from fcntl import ioctl
from tcpy.tuntap import open_tun
from tcpy.eth import EthernetHeader
from tcpy.arp import ARPTable


def to_run(name):
    return f"sudo ip link set dev {name} up && sudo ip route add dev {name} 10.0.0.0/24"

TEST_IP = "10.0.0.4"
TEST_MAC = "aa:bb:cc:dd:ee:ff"

# sudo arping -I tap0 10.0.0.1 -S 10.0.0.1

if __name__ == "__main__":
    (fd, (name, mode)) = open_tun("tap%d")
    print("Name: {name}".format(name=name))
    print(f"Please run:\n{to_run(name)}")

    table = ARPTable(TEST_IP, TEST_MAC)

    while True:
        raw = os.read(fd, 100)
        eth = EthernetHeader.decode(raw)

        if eth.is_arp():
            table.process_arp(fd, eth)
        elif eth.is_ip():
            print("IP HEADER !")
        else:
            print(f"Unknown header type: {eth}")
