import socket
import struct

from .constants import ICMP, IP_TCP, IPV4
from .ip_util import ip2int, ip_checksum


class IPHeader:

    """IPHeader representation"""

    fmt = "BBHHHBBHII"

    def __init__(
        self,
        version: int,
        ihl: int,
        tos: int,
        len: int,
        id: int,
        flags: int,
        frag_offset: int,
        ttl: int,
        proto: int,
        csum: int,
        saddr: int,
        daddr: int,
        payload: bytes,
    ):
        """Creates a new IP Header

        :version: 4 bit int to indicate the Internet Header format (=4 for IPv4)
        :ihl: 4 bit int that indicates the number of 32 bit words in the IP Header (max = 15 * 32 bits)
        :tos: type of service field (quality of service intended for the IP datagram)
        :len: the total length of the whole IP datagram (max length is 65535), if the IP datagram is too big it will be fragmented (TODO: implement fragmentation)
        :id: int used to index the datagram (used for reassembling fragmented IP datagrams), it's incremented by the sender (so the receiver can rebuild the datagram)
        :flags: defines control flags (whether fragmentation is allowed, if it's the last fragment, etc.)
        :frag_offset: Indicate the position of the fragment in the datagram (first has this set to 0)
        :ttl: time to live, used to count down the datagram's lifetime (every receiver decrements this by one), when it's zero the datagram is discarded and an ICMP message might be sent as a reply to indicate an error
        :proto: indicates the protocol (for instance 16 for UDP or 6 for TCP)
        :csum: the header checksum used to verify the integrity of the IP header
        :saddr: source address of the datagram
        :daddr: dest address of the datagram
        :payload: rest of the payload

        """

        self._version = version
        self._ihl = ihl
        self._tos = tos
        self.len = len
        self.id = id
        self._flags = flags
        self._frag_offset = frag_offset
        self._ttl = ttl
        self.proto = proto
        self._csum = csum
        self.saddr = saddr
        self.daddr = daddr
        self.payload = payload

    def is_tcp(self) -> bool:
        """Checks if the payload contains a TCP message

        :returns: a boolean

        """
        return self.proto == IP_TCP

    def is_icmp(self) -> bool:
        """Checks if the payload contains an ICMP message

        :returns: a boolean

        """
        return self.proto == ICMP

    def adjust_checksum(self) -> None:
        """adjusts the checksum to make sure it's valid
        """
        self._csum = 0
        # TODO improve that (it's not really efficient)
        self._csum = socket.htons(ip_checksum(self.encode()[:20]))

    def encode(self) -> bytes:
        """Encodes the given IPHeader into raw bytes

        :returns: raw bytes

        """
        version_ihl = self._version << 4 | self._ihl
        flags_fragoffset = self._flags << 13 | self._frag_offset

        raw = struct.pack(
            IPHeader.fmt,
            version_ihl,
            self._tos,
            self.len,
            self.id,
            flags_fragoffset,
            self._ttl,
            self.proto,
            self._csum,
            self.saddr,
            self.daddr,
        )
        return raw + self.payload

    @classmethod
    def decode(cls, raw: bytes) -> "IPHeader":
        """decodes the given raw bytes into an IP Header

        :raw: a list of bytes to decode
        :returns: an instance of IPHeader

        """

        # uint8_t version : 4;
        # uint8_t ihl : 4;
        # uint8_t tos;
        # uint16_t len;
        # uint16_t id;
        # uint16_t flags : 3;
        # uint16_t frag_offset : 13;
        # uint8_t ttl;
        # uint8_t proto;
        # uint16_t csum;
        # uint32_t saddr;
        # uint32_t daddr;

        fields = struct.unpack(cls.fmt, raw[:20])
        version_ihl = fields[0]
        flags_fragoffset = fields[4]
        vals = [
            (version_ihl & 0xF0) >> 4,
            version_ihl & 0x0F,
            *fields[1:4],
            (flags_fragoffset & 0xE000) >> 13,
            flags_fragoffset & 0x1F00,
            *fields[5:],
            raw[20:],
        ]
        ip_hdr = IPHeader(*vals)

        # TODO better way of checking the checksum

        # We compute the checksum only on the header (and not the data) for IPHeaders
        computed_csum = ip_checksum(raw[:20])
        if computed_csum != 0:
            raise ValueError(
                f"Invalid checksum for IPHeader, got: {computed_csum}, expected 0"
            )

        return ip_hdr

    def is_supported(self) -> bool:
        """checks if the given IP header is supported

        :returns: A boolean indicating if it's supported

        """

        # TODO logging ?
        # TODO ICMP error if ttl is zero
        return self._version == 4 and self._ihl >= 5 and self._ttl != 0

    def __repr__(self) -> str:
        return f"{self.__dict__}"

    def reply(self, src_ip: str, payload: bytes, proto: int) -> "IPHeader":
        """Reply to an IP datagram

        :src_ip: the source IP as a string
        :payload: the payload to encode
        :proto: The protocol (ICMP, TCP)
        :returns: an IPHeader containing the reply

        """

        # TODO: don't hardcode header length
        ip_r = IPHeader(
            # TODO don't hardcode the version
            version=IPV4,
            ihl=0x05,
            tos=0,
            # The length of the datagram is the length of the payload + the length of the header (20)
            len=socket.htons(len(payload) + 20),
            id=self.id,
            # TODO allow flags
            # For now flags are only used to indicate fragmentation / if there are more fragmented
            # packets to come, for now let's ignore this
            flags=0,
            frag_offset=socket.htons(0x4000),
            ttl=64,
            proto=proto,
            # the checksum will be computed later on
            csum=0,
            saddr=socket.htonl(ip2int(src_ip)),
            daddr=self.saddr,
            payload=payload,
        )
        ip_r.adjust_checksum()

        return ip_r
