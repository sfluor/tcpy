import socket
import struct

from .constants import TCP_ACK, TCP_SYN
from .ip import IPHeader
from .ip_util import ip_checksum, sum_by_16bits

TCP_HEADER_SIZE = 20


class TCPHeader:

    """TCPHeader representation"""

    fmt = "!HHIIBBHHH"

    def __init__(
        self,
        src_port: int,
        dst_port: int,
        seq: int,
        ack: int,
        hl: int,
        flags: int,
        win_size: int,
        csum: int,
        uptr: int,
        additional_fields: bytes,
        payload: bytes,
    ):
        """creates a TCPHeader instance

        :src_port: source network port
        :dst_port: destination network port
        :seq: sequence number (it's the TCP segment's window index), it contains the Initial Sequence Number during handshake
        :ack: the acknowledgment number contains the window's index of the next expected bytes
        :hl: the header length in 32-bit words (multiply by 4 to get in bytes)
        :flags: uint8 sized: |C|E|U|A|P|R|S|F, see https://en.wikipedia.org/wiki/Transmission_Control_Protocol for descriptions
        :win_size: number of bytes the receiver is willing to accept (max value is 65535 since it's supposed to be encoded in a 2 bytes field)
        :csum: checksum of the TCP segment (uses the same algorithm as the ip_checksum but also includes a pseudo-header from the IP datagram)
        :uptr: used when the U-flag is set, it indicates the position of the urgent data in the stream
        :additional_fields: additional_fields in the header not yet supported (in form of bytes)
        :payload: payload contained in the TCP datagram

        """
        self.src_port = src_port
        self.dst_port = dst_port
        self._seq = seq
        self._ack = ack
        self._hl = hl
        self._flags = flags
        self._win_size = win_size
        self._csum = csum
        self._uptr = uptr
        self._additional_fields = additional_fields
        self._payload = payload

    @classmethod
    def decode(cls, raw: bytes) -> "TCPHeader":
        """decodes the given raw bytes into an TCPHeader

        :raw: a list of bytes to decode
        :returns: an instance of TCPHeader

        """

        # 0                              15                              31
        # -----------------------------------------------------------------
        # |          source port          |       destination port        |
        # -----------------------------------------------------------------
        # |                        sequence number                        |
        # -----------------------------------------------------------------
        # |                     acknowledgment number                     |
        # -----------------------------------------------------------------
        # |  HL   | rsvd  |C|E|U|A|P|R|S|F|        window size            |
        # -----------------------------------------------------------------
        # |         TCP checksum          |       urgent pointer          |
        # -----------------------------------------------------------------

        # TODO decode additional fields such as mss

        # TODO verify checksum

        (src_port, dst_port, seq, ack, hl, flags, win_size, csum, uptr) = struct.unpack(
            cls.fmt, raw[:TCP_HEADER_SIZE]
        )
        hl = hl >> 4
        additional_fields = raw[TCP_HEADER_SIZE : 4 * hl]
        payload = raw[4 * hl :]
        return TCPHeader(
            src_port=src_port,
            dst_port=dst_port,
            seq=seq,
            ack=ack,
            hl=hl,
            flags=flags,
            win_size=win_size,
            csum=csum,
            uptr=uptr,
            additional_fields=additional_fields,
            payload=payload,
        )

    def encode(self) -> bytes:
        """encodes the given TCPHeader into raw bytes

        :returns: a raw bytes representation of the given TCPHeader

        """
        return (
            struct.pack(
                TCPHeader.fmt,
                self.src_port,
                self.dst_port,
                self._seq,
                self._ack,
                self._hl << 4,
                self._flags,
                self._win_size,
                self._csum,
                self._uptr,
            )
            + self._additional_fields
            + self._payload
        )

    def adjust_checksum(self, ip_hdr: IPHeader) -> None:
        """adjusts the checksum to make sure it's valid

        :ip_hdr: IPHeader required to generate th pseudo header
        """
        self._csum = 0
        # TODO improve that (it's not really efficient)
        self._csum = self.checksum(ip_hdr)

    def checksum(self, ip_hdr: IPHeader) -> int:
        """computes the TCP checksum for the given TCP datagram and given IPHeader

        :ip_hdr: the IPHeader to use when computing the checksum
        :returns: An integer representing the checksum

        """

        # The TCP checksum includes a pseudo IP Header with the following data:
        # uint32_t saddr;
        # uint32_t daddr;
        # uint8_t zero;
        # uint8_t proto;
        # uint16_t len;

        iphdr_fmt = "IIBBH"

        # TODO Find a better way to figure out length and change this when adding new fields
        length = socket.htons(
            TCP_HEADER_SIZE + len(self._additional_fields) + len(self._payload)
        )

        pseudo_hdr = struct.pack(
            # Swap source / dest addresses
            iphdr_fmt,
            ip_hdr.daddr,
            ip_hdr.saddr,
            0,
            ip_hdr.proto,
            length,
        )

        return ip_checksum(self.encode(), start=sum_by_16bits(pseudo_hdr))

    def reply(self, ip_hdr: IPHeader) -> "TCPHeader":
        """Reply to the given TCP datagram
        warning: it modifies the current TCPHeader in place
        it returns the current one for convenience

        :ip_hdr:  the original IP header
        :returns: a new TCPHeader (built from the old one)

        """
        # Swap ports
        self.src_port, self.dst_port = self.dst_port, self.src_port

        if self._flags & TCP_SYN:
            self._flags |= TCP_ACK
            self._ack = self._seq + 1
            # TODO change this sequence number
            self._seq = socket.htonl(1234)

        # TODO support more TCP options
        self._hl = 5
        self._additional_fields = b""

        self.adjust_checksum(ip_hdr)
        return self
