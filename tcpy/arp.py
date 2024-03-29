import array
import socket
import struct
from typing import Callable

from .constants import ARP_ETHERNET, ARP_IPV4, ARP_REPLY, ARP_REQUEST


def _check_opcode_fn(opcode: int) -> Callable[["ARPHeader"], bool]:
    def f(self: "ARPHeader") -> bool:
        return self.opcode == opcode

    return f


class ARPHeader:

    """ARPHeader representation"""

    fmt = "HHBBH"

    # TODO enum for opcode
    def __init__(
        self,
        hwtype: int,
        protype: int,
        hwsize: int,
        prosize: int,
        opcode: int,
        data: bytes,
    ):
        """Creates a new ARPHeader

        :hwtype: Link layer type used (2 octet int), for instance ARP_ETHERNET
        :protype: Protocol type (2 octet int), for instance ARP_IPV4
        :hwsize: size of hardware field (1 octet int)
        :prosize: size of protocol field (1 octet int)
        :opcode: type of the ARP message (2 octet int), can be ARP request, ARP reply, RARP request, RARP reply
        :data: raw bytes containing the payload of the ARP message

        """

        self.hwtype = hwtype
        self.protype = protype
        self._hwsize = hwsize
        self._prosize = prosize
        self.opcode = opcode
        self._data = data

    is_arp_request = _check_opcode_fn(ARP_REQUEST)
    is_arp_reply = _check_opcode_fn(ARP_REPLY)

    def is_supported(self) -> bool:
        """checks if the current ARPHeader is supported

        :returns: A boolean indicating if the current ARP Header is supported

        """
        return self.hwtype == ARP_ETHERNET and self.protype == ARP_IPV4

    def ipv4_data(self) -> "ARPIPv4":
        """decodes the IPv4 data in the ARP packet
        throws an exception if the ARP packet does not have IPv4 data

        :returns: An ARPIPv4 instance

        """

        if not self.protype == ARP_IPV4:
            raise ValueError("ARP Header does not have IPv4 data")

        return ARPIPv4.decode(self._data)

    def replace_data(self, data: bytes) -> None:
        """replaces the payload contained in the ARP message

        :data: raw bytes representing the new data

        """
        self._data = data

    def encode(self) -> bytes:
        """encodes the given ARP Header into raw bytes

        :returns: raw bytes

        """

        # uint16_t hwtype;
        # uint16_t protype;
        # unsigned char hwsize;
        # unsigned char prosize;
        # uint16_t opcode;
        # unsigned char data[];
        raw = struct.pack(
            ARPHeader.fmt,
            socket.htons(self.hwtype),
            socket.htons(self.protype),
            self._hwsize,
            self._prosize,
            socket.htons(self.opcode),
        )

        return raw + self._data

    @classmethod
    def decode(cls, raw: bytes) -> "ARPHeader":
        """decodes the given raw bytes into an ARP Header

        :raw: a list of bytes to decode
        :returns: an instance of ARPHeader

        """
        # uint16_t hwtype;
        # uint16_t protype;
        # unsigned char hwsize;
        # unsigned char prosize;
        # uint16_t opcode;
        # unsigned char data[];
        arp_hdr = struct.unpack(cls.fmt, raw[:8])
        hwtype = socket.htons(arp_hdr[0])
        protype = socket.htons(arp_hdr[1])
        hwsize = arp_hdr[2]
        prosize = arp_hdr[3]
        opcode = socket.htons(arp_hdr[4])
        return ARPHeader(
            hwtype=hwtype,
            protype=protype,
            hwsize=hwsize,
            prosize=prosize,
            opcode=opcode,
            data=raw[8:],
        )


class ARPIPv4:

    """ARPIPv4 data"""

    def __init__(self, smac: bytes, sip: str, dmac: bytes, dip: str):
        """creates a new ARPIPv4 instance

        :smac: The source MAC address (6 bytes)
        :sip: The source IP (str)
        :dmac: The destination MAC address (6 bytes)
        :dip: The destination IP (str)

        """

        self.smac = smac
        self.sip = sip
        self.dmac = dmac
        self.dip = dip

    def encode(self) -> bytes:
        """encodes ARPIPv4 data into raw bytes (shape of a struct arp_ipv4)

        :returns: raw bytes representing a struct arp_ipv4

        """

        # unsigned char smac[6];
        # uint32_t sip;
        # unsigned char dmac[6];
        # uint32_t dip;

        # TODO Improve this
        return (
            self.smac
            + socket.inet_aton(self.sip)
            + self.dmac
            + socket.inet_aton(self.dip)
        )

    @classmethod
    def decode(cls, raw: bytes) -> "ARPIPv4":
        """decodes ARPIPv4 data from raw bytes of a struct arp_ipv4

        :raw: A list of bytes
        :returns: an ARPIPv4 instance

        """

        # unsigned char smac[6];
        # uint32_t sip;
        # unsigned char dmac[6];
        # uint32_t dip;

        smac = raw[:6]
        dmac = raw[10:16]
        sip = socket.inet_ntoa(raw[6:10])
        dip = socket.inet_ntoa(raw[16:20])
        return ARPIPv4(smac=smac, sip=sip, dmac=dmac, dip=dip)

    def __repr__(self) -> str:
        return "Source: ({}, {}), Dest: ({}, {})".format(
            fmt_mac(self.smac), self.sip, fmt_mac(self.dmac), self.dip
        )


def fmt_mac(tup: bytes) -> str:
    """ converts a list of bytes into a readable mac address"""
    return "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}".format(*tup)


def mac2b(addr: str) -> bytes:
    """ converts a string mac addres to bytes"""
    return array.array("B", [int(x, 16) for x in addr.split(":")]).tobytes()
