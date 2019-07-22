import struct
import socket

from .constants import ETH_P_ARP, ETH_P_IP
from .arp import ARPHeader


class EthernetHeader:

    """EthernetHeader representation"""

    def __init__(self, dmac, smac, typ, payload):
        """creates a new EthernetHeader

        :dmac: the destination mac address (tuple of 6 ints)
        :smac: the source mac address (tuple of 6 ints)
        :typ: The ethertype for the header (2 octet int) that indicates the length or the type of the payload
        it's the type of the payload if greater or requal to 1536, otherwise it's the length of the payload)
        :payload: raw bytes representing the payload

        """
        self._dmac = dmac
        self._smac = smac
        self._typ = typ
        self._payload = payload

    @classmethod
    def decode(cls, raw):
        """decodes an ethernet header from raw bytes

        :raw: A list of bytes
        :returns: An EthernetHeader instance

        """
        # unsigned char dmac[6];
        # unsigned char smac[6];
        # uint16_t ethertype;
        # unsigned char payload[];
        eth_hdr = struct.unpack("6B6BH", raw[:14])
        dmac = eth_hdr[:6]
        smac = eth_hdr[6:12]
        typ = socket.htons(eth_hdr[12])
        payload = raw[14:]
        return EthernetHeader(dmac=dmac, smac=smac, typ=typ, payload=payload)

    def is_arp(self):
        """checks if the current ethernet header contains an ARP header

        :returns: A boolean indicating if the header contains an ARPHeader

        """
        return self._typ == ETH_P_ARP

    def arp_hdr(self):
        """extract an ARPHeader from the current EthernetHeader
        throws an exception if the EthernetHeader does not contain an ARPHeader

        :returns: An ARPHeader instance

        """
        if not self.is_arp():
            raise ValueError("EthernetHeader does not contain an ARP Header")

        return ARPHeader.decode(self._payload)

    def is_ip(self):
        """checks if the current ethernet header contains an IP header

        :returns: A boolean indicating if the header contains an IPHeader

        """
        return self._typ == ETH_P_IP