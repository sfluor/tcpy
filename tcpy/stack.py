import os
import socket
from multiprocessing import Process
from typing import Optional

from tcpy.arp import mac2b
from tcpy.arp_table import ARPTable
from tcpy.constants import ETH_P_IP
from tcpy.eth import EthernetHeader
from tcpy.ip import IPHeader, icmpv4_reply
from tcpy.tuntap import open_tun


def to_run(name: str) -> str:
    return f"sudo ip link set dev {name} up && sudo ip route add dev {name} 10.0.0.0/24"


class Stack:

    """A TCP/IP Stack"""

    def __init__(
        self,
        ip: str = "10.0.0.4",
        mac: str = "aa:bb:cc:dd:ee:ff",
        interf: str = "tap%d",
    ):
        """creates a TCP/IP Stack

        :ip: ip to use
        :mac: mac address to use
        :interf: name for the tun/tap interface

        """

        self._ip = ip
        self._mac = mac
        self._interf = interf
        self.proc: Optional[Process] = None
        self.fd = 0
        self.table = ARPTable(self._ip, self._mac)

    def start(self) -> None:
        """starts the stack in a separate process """
        self.proc = Process(target=self.start_in_fg)
        self.proc.start()

    def stop(self) -> None:
        """stops the stack if it was started in a separate process

        throws an exception if it was not started
        """
        if self.proc is None:
            raise ValueError("Network stack was not started in a separate process")

        self.proc.terminate()

    def start_in_fg(self) -> None:
        """starts the stack on the foreground"""
        (self.fd, (name, mode)) = open_tun(self._interf)

        print("Name: {name}".format(name=name))
        print(f"Please run:\n{to_run(name)}")

        while True:
            # TODO make this number configurable
            raw = os.read(self.fd, 200)
            eth = EthernetHeader.decode(raw)

            if eth.is_arp():
                self._handle_arp(eth)
            elif eth.is_ip():
                self._handle_ip(eth)
            else:
                print(f"Unknown header type: {eth}, type: {eth.typ}")

    def _handle_arp(self, eth: EthernetHeader) -> None:
        """handles an ARP message

        :eth: an EthernetHeader instance
        """
        print("ARP Header")
        resp = self.table.process_arp(eth)
        if resp is not None:
            os.write(self.fd, resp.encode())

    def _handle_ip(self, eth: EthernetHeader) -> None:
        """handles an IP message

        :eth: an EthernetHeader instance
        """
        ip_hdr = eth.ip_hdr()
        if ip_hdr.is_icmp():
            self._handle_icmp(eth, ip_hdr)
        else:
            print(f"Unknown IP/? Header, protocol: {ip_hdr.proto}")

    def _handle_icmp(self, eth: EthernetHeader, ip_hdr: IPHeader) -> None:
        """handles an ICMP message

        :eth: an EthernetHeader instance
        :ip_hdr: an IPHeader instance
        """
        print("ICMP Header")
        icmp_hdr = ip_hdr.icmp_hdr()
        icmp_r = icmpv4_reply(self._ip, icmp_hdr, ip_hdr)
        dmac = self.table.get_mac_for_ip(socket.htonl(ip_hdr.saddr))
        resp = EthernetHeader(
            typ=ETH_P_IP, smac=mac2b(self._mac), dmac=dmac, payload=icmp_r.encode()
        )
        os.write(self.fd, resp.encode())
