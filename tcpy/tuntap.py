import os
import struct
from fcntl import ioctl
from typing import Tuple

from .constants import IFF_NO_PI, IFF_TAP, TUNSETIFF

IFREQ_STRUCT = "16sH"


def open_tun(interf: str) -> Tuple[int, Tuple[str, int]]:
    """opens a tun/tap interface

    :interf: A string for the name of the interface
    :returns: A tuple (fd: int, (name: str, mode: int))

    """
    fd = os.open("/dev/net/tun", os.O_RDWR)
    mode = IFF_TAP | IFF_NO_PI
    ifs = ioctl(fd, TUNSETIFF, encode_ifreq(interf, mode))
    return (fd, decode_ifreq(ifs))


def encode_ifreq(name: str, mode: int) -> bytes:
    """encode_ifreq encodes the given name and mode into an
    ifreq struct

    :name: Name for the network interface (str)
    :mode: Mode to use (int)
    :returns: raw bytes representing an ifreq struct

    """
    return struct.pack(IFREQ_STRUCT, name.encode(), mode)


def decode_ifreq(raw: bytes) -> Tuple[str, int]:
    """Decodes the name and mode from raw bytes representing an ifreq struct

    :raw: A list of bytes
    :returns: A tuple (name: str, mode: int)

    """
    tup = struct.unpack(IFREQ_STRUCT, raw)
    return (tup[0].strip(b"\x00").decode(), tup[1])
