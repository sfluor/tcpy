import socket
import struct

from .ip_util import ip_checksum


class ICMPv4Header:

    """ICMPv4Header representation"""

    fmt = "BBH"

    def __init__(self, typ: int, code: int, csum: int, data: bytes):
        """Creates a new ICMPv4Header

        :typ: int for the purpose of the message (there are 42 different values, see: https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml)
        :code: int that describes the meaning of the message (for instance the reason in case of an error)
        :csum: same checksum field as in the IPv4 header
        :data: additional data in raw bytes (have to be decoded)
        """

        self._typ = typ
        self._code = code
        self._csum = csum
        self._data = data

    def adjust_checksum(self) -> None:
        """adjusts the checksum to make sure it's valid
        """
        self._csum = 0
        # TODO improve that (it's not really efficient)
        self._csum = socket.htons(ip_checksum(self.encode()))

    def encode(self) -> bytes:
        """encodes the given ICMPv4Header into raw bytes

        :returns: raw bytes representing the ICMPv4Header encoded

        """

        # uint8_t type;
        # uint8_t code;
        # uint16_t csum;
        # uint8_t data[];

        return (
            struct.pack(ICMPv4Header.fmt, self._typ, self._code, self._csum)
            + self._data
        )

    @classmethod
    def decode(cls, raw: bytes) -> "ICMPv4Header":
        """decodes the given raw bytes into an ICMPv4Header

        :raw: a list of bytes to decode
        :returns: an instance of ICMPv4Header

        """

        # uint8_t type;
        # uint8_t code;
        # uint16_t csum;
        # uint8_t data[];

        (typ, code, csum) = struct.unpack(cls.fmt, raw[:4])
        icmp = ICMPv4Header(typ=typ, code=code, csum=csum, data=raw[4:])

        # TODO better way of checking the checksum
        computed_csum = ip_checksum(raw)
        if computed_csum != 0:
            raise ValueError(
                f"Invalid checksum for ICMPv4Header, got: {computed_csum}, expected 0"
            )

        return icmp
