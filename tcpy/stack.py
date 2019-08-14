import os
import socket
from multiprocessing import Process
from typing import Optional

from .arp import mac2b
from .arp_table import ARPTable
from .constants import ETH_P_IP, ICMP, IP_TCP
from .eth import EthernetHeader
from .icmpv4 import ICMPv4Header
from .ip import IPHeader
from .tcp import TCPHeader
from .tuntap import open_tun


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
            # hex_debug(raw, desc="input")
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
        ip_hdr = IPHeader.decode(eth.payload)
        if ip_hdr.is_icmp():
            self._handle_icmp(eth, ip_hdr)
        elif ip_hdr.is_tcp():
            self._handle_tcp(eth, ip_hdr)
        else:
            print(f"Unknown IP/? Header, protocol: {ip_hdr.proto}")

    def _handle_icmp(self, eth: EthernetHeader, ip_hdr: IPHeader) -> None:
        """handles an ICMP message

        :eth: an EthernetHeader instance
        :ip_hdr: an IPHeader instance
        """
        print("ICMP Header")

        icmp_hdr = ICMPv4Header.decode(ip_hdr.payload)
        icmp_r = icmp_hdr.reply()
        ip_r = ip_hdr.reply(self._ip, icmp_r.encode(), ICMP)

        self.ip_output(ip_hdr.saddr, ip_r.encode())

    def _handle_tcp(self, eth: EthernetHeader, ip_hdr: IPHeader) -> None:
        """handles a TCP message

        :eth: an EthernetHeader instance
        :ip_hdr: an IPHeader instance
        """
        print("TCP Header")

        tcp_hdr = TCPHeader.decode(ip_hdr.payload)
        tcp_r = tcp_hdr.reply(ip_hdr)
        ip_r = ip_hdr.reply(self._ip, tcp_r.encode(), IP_TCP)

        self.ip_output(ip_hdr.saddr, ip_r.encode())

    def ip_output(self, daddr: int, payload: bytes) -> None:
        """outputs the given payload through an ethernet eth_p_ip frame

        :daddr: destination address
        :payload: payload in bytes

        """
        resp = self._build_eth_reply(ETH_P_IP, daddr, payload)
        encoded = resp.encode()

        # hex_debug(encoded, "output")
        os.write(self.fd, encoded)

    def _build_eth_reply(self, typ: int, daddr: int, payload: bytes) -> EthernetHeader:
        dmac = self.table.get_mac_for_ip(socket.htonl(daddr))
        return EthernetHeader(
            typ=typ, smac=mac2b(self._mac), dmac=dmac, payload=payload
        )


def hex_debug(raw: bytes, desc: str = "") -> None:
    """Prints the given bytes in hexadecimal with a description

    :raw: The bytes to print
    :desc: A description (defaults to empty)

    """
    hexa = " ".join(["{:02x}".format(x) for x in raw])

    print(f"-----  Debug {desc} -----\n{hexa}\n{'-' * 20}")
