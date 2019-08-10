import socket
import struct

from .arp import ARPHeader
from .constants import ETH_P_ARP, ETH_P_IP
from .ip import IPHeader


class EthernetHeader:

    """EthernetHeader representation"""

    def __init__(self, dmac: bytes, smac: bytes, typ: int, payload: bytes):
        """creates a new EthernetHeader

        :dmac: the destination mac address (tuple of 6 ints)
        :smac: the source mac address (tuple of 6 ints)
        :typ: The ethertype for the header (2 octet int) that indicates the length or the type of the payload
        it's the type of the payload if greater or requal to 1536, otherwise it's the length of the payload)
        :payload: raw bytes representing the payload

        """
        self.dmac = dmac
        self.smac = smac
        self.typ = typ
        self._payload = payload

    def encode(self) -> bytes:
        """encodes the given EthernetHeader into raw bytes

        :returns: raw bytes
        """

        # unsigned char dmac[6];
        # unsigned char smac[6];
        # uint16_t ethertype;
        # unsigned char payload[];

        t = struct.pack("H", socket.htons(self.typ))
        return self.dmac + self.smac + t + self._payload

    @classmethod
    def decode(cls, raw: bytes) -> "EthernetHeader":
        """decodes an ethernet header from raw bytes

        :raw: A list of bytes
        :returns: An EthernetHeader instance

        """
        # unsigned char dmac[6];
        # unsigned char smac[6];
        # uint16_t ethertype;
        # unsigned char payload[];
        dmac = raw[:6]
        smac = raw[6:12]
        typ = socket.htons(struct.unpack("H", raw[12:14])[0])
        payload = raw[14:]
        return EthernetHeader(dmac=dmac, smac=smac, typ=typ, payload=payload)

    def is_arp(self) -> bool:
        """checks if the current ethernet header contains an ARP header

        :returns: A boolean indicating if the header contains an ARPHeader

        """
        return self.typ == ETH_P_ARP

    def arp_hdr(self) -> "ARPHeader":
        """extract an ARPHeader from the current EthernetHeader
        throws an exception if the EthernetHeader does not contain an ARPHeader

        :returns: An ARPHeader instance

        """
        if not self.is_arp():
            raise ValueError("EthernetHeader does not contain an ARP Header")

        return ARPHeader.decode(self._payload)

    def is_ip(self) -> bool:
        """checks if the current ethernet header contains an IP header

        :returns: A boolean indicating if the header contains an IPHeader

        """
        return self.typ == ETH_P_IP

    def ip_hdr(self) -> IPHeader:
        """extract an IPHeader from the current EthernetHeader
        throws an exception if the EthernetHeader does not contain an IPHeader

        :returns: An IPHeader instance

        """
        if not self.is_ip():
            raise ValueError("EthernetHeader does not contain an IP Header")

        return IPHeader.decode(self._payload)
