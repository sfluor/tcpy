import struct
import socket

from .constants import ARP_ETHERNET, ARP_IPV4


class ARPHeader:

    """ARPHeader representation"""

    def __init__(self, hwtype, protype, hwsize, prosize, opcode, data):
        """Creates a new ARPHeader

        :hwtype: Link layer type used (2 octet int), for instance ARP_ETHERNET
        :protype: Protocol type (2 octet int), for instance ARP_IPV4
        :hwsize: size of hardware field (1 octet int)
        :prosize: size of protocol field (1 octet int)
        :opcode: type of the ARP message (2 octet int), can be ARP request, ARP reply, RARP request, RARP reply
        :data: raw bytes containing the payload of the ARP message

        """

        self._hwtype = hwtype
        self._protype = protype
        self._hwsize = hwsize
        self._prosize = prosize
        self._opcode = opcode
        self._data = data

    def is_supported(self):
        """checks if the current ARPHeader is supported

        :returns: A boolean indicating if the current ARP Header is supported

        """
        return self._hwtype == ARP_ETHERNET and self._protype == ARP_IPV4

    def ipv4_data(self):
        """decodes the IPv4 data in the ARP packet
        throws an exception if the ARP packet does not have IPv4 data

        :returns: An ARPIPv4 instance

        """

        if not self._protype == ARP_IPV4:
            raise ValueError("ARP Header does not have IPv4 data")

        return ARPIPv4.decode(self._data)

    @classmethod
    def decode(cls, raw):
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
        arp_hdr = struct.unpack("HHBBH", raw[:8])
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

    def __init__(self, smac, sip, dmac, dip):
        """creates a new ARPIPv4 instance

        :smac: The source MAC address (6 int tuple)
        :sip: The source IP (int)
        :dmac: The destination MAC address (6 int tuple)
        :dip: The destination IP (int)

        """

        self._smac = smac
        self._sip = sip
        self._dmac = dmac
        self._dip = dip

    @classmethod
    def decode(cls, raw):
        """decodes ARPIPv4 data from raw bytes of a struct arp_ipv4

        :raw: A list of bytes
        :returns: an ARPIPv4 instance

        """

        # unsigned char smac[6];
        # uint32_t sip;
        # unsigned char dmac[6];
        # uint32_t dip;

        ipv4 = struct.unpack("6BI6BI", raw[:24])
        smac = ipv4[:6]
        sip = ipv4[6]
        dmac = ipv4[7:13]
        dip = ipv4[13]
        return ARPIPv4(smac=smac, sip=sip, dmac=dmac, dip=dip)

    def __repr__(self):
        return "Source: ({}, {}), Dest: ({}, {})".format(
            _fmt_mac(self._smac), self._sip, _fmt_mac(self._dmac), self._dip
        )


def _fmt_mac(tup):
    return "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}".format(*tup)
