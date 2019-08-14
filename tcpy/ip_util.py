import socket
import struct


def ip_checksum(hdr_raw: bytes, start: int = 0) -> int:
    """Computes the IP checksum for the given raw IP header

    From: Taken from https://tools.ietf.org/html/rfc1071

    :hdr_raw: Raw IP Header in bytes
    :start: optional parameter to offset the start checksum
    :returns: an int representing the checksum value

    """

    csum = start + sum_by_16bits(hdr_raw)

    while csum >> 16:
        csum = (csum & 0xFFFF) + (csum >> 16)

    return csum ^ 0xFFFF


def sum_by_16bits(raw: bytes) -> int:
    """sums the given raw bytes 16bits by 16bits and retun the results

    :raw: Raw bytes
    :returns: int for the sum 16 bits by 16 bits

    """
    csum, idx = 0, 0
    length = len(raw)

    while idx + 1 < length:
        csum += struct.unpack("!H", raw[idx : idx + 2])[0]
        idx += 2

    if idx < length:
        csum += int(raw[idx])

    return csum


def ip2int(addr: str) -> int:
    """convert an IP string to an int
    """
    return struct.unpack("!I", socket.inet_aton(addr))[0]


def int2ip(addr: int) -> str:
    """convert an IP int to a string
    """
    return socket.inet_ntoa(struct.pack("!I", addr))
