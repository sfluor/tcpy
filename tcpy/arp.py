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
