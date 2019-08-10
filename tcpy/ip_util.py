import socket
import struct


def ip_checksum(hdr_raw: bytes) -> int:
    """Computes the IP checksum for the given raw IP header

    From: Taken from https://tools.ietf.org/html/rfc1071

    :hdr_raw: Raw IP Header in bytes
    :returns: an int representing the checksum value

    """

    csum, idx = 0, 0
    length = len(hdr_raw)

    while idx + 1 < length:
        csum += struct.unpack("!H", hdr_raw[idx : idx + 2])[0]
        idx += 2

    if idx < length:
        csum += int(hdr_raw[idx])

    while csum >> 16:
        csum = (csum & 0xFFFF) + (csum >> 16)

    return csum ^ 0xFFFF


def ip2int(addr: str) -> int:
    """convert an IP string to an int
    """
    return struct.unpack("!I", socket.inet_aton(addr))[0]


def int2ip(addr: int) -> str:
    """convert an IP int to a string
    """
    return socket.inet_ntoa(struct.pack("!I", addr))