#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from fcntl import ioctl
import struct
import socket
from tcpy.tuntap import open_tun
from tcpy.eth import EthernetHeader


def to_run(name):
    return f"sudo ip link set dev {name} up && sudo ip route add dev {name} 10.0.0.0/24"



# sudo arping -I tap0 10.0.0.1 -S 10.0.0.1

if __name__ == "__main__":
    (fd, (name, mode)) = open_tun("tap%d")
    print("Name: {name}".format(name=name))
    print(f"Please run:\n{to_run(name)}")

    while True:
        raw = os.read(fd, 100)
        hdr = EthernetHeader.decode(raw)

        if hdr.is_arp():
            arp = hdr.arp_hdr()
            print(arp)
            if not arp.is_supported():
                print("unsupported layer type (not ethernet or not ipv4)")

        elif hdr.is_ip():
            print("IP HEADER !")

        else:
            print(f"Unknown header type: {hdr}")

        print(len(raw))
