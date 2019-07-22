import os
from fcntl import ioctl
import struct
from .constants import IFF_TAP, IFF_NO_PI, TUNSETIFF

IFREQ_STRUCT = "16sH"


def open_tun(interf):
    """opens a tun/tap interface

    :interf: A string for the name of the interface
    :returns: A tuple (fd: int, (name: str, mode: int))

    """
    fd = os.open("/dev/net/tap", os.O_RDWR)
    mode = IFF_TAP | IFF_NO_PI
    ifs = ioctl(fd, TUNSETIFF, encode_ifreq(interf.encode(), mode))
    return (fd, decode_ifreq(ifs))


def encode_ifreq(name, mode):
    """encode_ifreq encodes the given name and mode into an
    ifreq struct

    :name: Name for the network interface
    :mode: Mode to use
    :returns: raw bytes representing an ifreq struct

    """
    return struct.pack(IFREQ_STRUCT, name, mode)


def decode_ifreq(raw):
    """Decodes the name and mode from raw bytes representing an ifreq struct

    :raw: A list of bytes
    :returns: A tuple (name: str, mode: int)

    """
    tup = struct.unpack(IFREQ_STRUCT, raw)
    return (tup[0].strip(b"\x00").decode(), tup[1])
