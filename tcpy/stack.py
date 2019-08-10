import os
import socket

from tcpy.arp import mac2b
from tcpy.arp_table import ARPTable
from tcpy.constants import ETH_P_IP
from tcpy.eth import EthernetHeader
from tcpy.ip import icmpv4_reply
from tcpy.tuntap import open_tun


def to_run(name: str) -> str:
    return f"sudo ip link set dev {name} up && sudo ip route add dev {name} 10.0.0.0/24"


def start_stack(ip: str, mac: str, interf: str) -> None:
    """starts a TCP/IP stack

    :ip: IP to use
    :mac: mac address to use
    :interf: name for the tun/tap interface
    """

    (fd, (name, mode)) = open_tun(interf)

    print("Name: {name}".format(name=name))
    print(f"Please run:\n{to_run(name)}")

    table = ARPTable(ip, mac)

    while True:
        raw = os.read(fd, 200)
        eth = EthernetHeader.decode(raw)

        if eth.is_arp():
            print("ARP Header")
            resp = table.process_arp(eth)
            if resp is not None:
                os.write(fd, resp.encode())

        elif eth.is_ip():
            print("IP Header")
            ip_hdr = eth.ip_hdr()
            if ip_hdr.is_icmp():
                print("\tICMP Header")
                icmp_hdr = ip_hdr.icmp_hdr()
                icmp_r = icmpv4_reply(ip, icmp_hdr, ip_hdr)
                dmac = table.get_mac_for_ip(socket.htonl(ip_hdr.saddr))
                resp = EthernetHeader(
                    typ=ETH_P_IP, smac=mac2b(mac), dmac=dmac, payload=icmp_r.encode()
                )
                os.write(fd, resp.encode())
        else:
            print(f"Unknown header type: {eth}, type: {eth.typ}")
