from tcpy.ip import IPHeader
from tcpy.tcp import TCPHeader

from .utils import run_cmd_with_stack


def test_tcp_handshake() -> None:
    run_cmd_with_stack(["nc", "10.0.0.4", "1337", "-z", "-w", "1"])


def test_decode_encode_tcp_hdr() -> None:
    raw = [
        # Source port
        0x84,
        0xCC,
        # Dest port
        0x05,
        0x39,
        # sequence number: big number
        0x6C,
        0xCC,
        0xD6,
        0x21,
        # Ack number: 0
        0x00,
        0x00,
        0x00,
        0x00,
        # HL: 0xa0 >> 4 = 10
        0xA0,
        # Flags: 0x02
        0x02,
        # Window size: 0x7210
        0x72,
        0x10,
        # Checksum: 0xfc5c
        0xFC,
        0x5C,
        # Urgent pointer: 0
        0x00,
        0x00,
        # Additional fields (not supported for now)
        0x02,
        0x04,
        0x05,
        0xB4,
        0x04,
        0x02,
        0x08,
        0x0A,
        0x90,
        0xCE,
        0xB0,
        0x22,
        0x00,
        0x00,
        0x00,
        0x00,
        0x01,
        0x03,
        0x03,
        0x07,
    ]

    res = TCPHeader.decode(bytes(raw))
    res_dict = res.__dict__
    expected = TCPHeader(
        src_port=33996,
        dst_port=1337,
        seq=1825363489,
        ack=0,
        hl=10,
        flags=0x002,
        win_size=0x7210,
        csum=0xFC5C,
        uptr=0,
        additional_fields=bytes(raw)[20:],
        payload=bytes([]),
    ).__dict__

    assert len(res_dict) == len(expected)
    for k, v in res_dict.items():
        assert v == expected[k]

    encoded = res.encode()
    assert bytes(raw) == encoded


def test_tcp_checksum() -> None:
    raw = [
        # Beginning of IPHeader
        0x45,
        0x00,
        0x00,
        0x3C,
        0x61,
        0xAF,
        0x40,
        0x00,
        0x40,
        0x06,
        0x0D,
        0x5F,
        0xC0,
        0xA8,
        0x01,
        0x02,
        0x0A,
        0x00,
        0x00,
        0x04,
        # End of IPHeader
        # Start of TCPHeader
        0xAC,
        0x40,
        0x05,
        0x39,
        0xB0,
        0xF6,
        0xD1,
        0xA6,
        0x00,
        0x00,
        0x00,
        0x00,
        0xA0,
        0x02,
        0x72,
        0x10,
        # Expected checksum is 0x1e22
        # 0x1E,
        # 0x22,
        0x00,
        0x00,
        0x00,
        0x00,
        0x02,
        0x04,
        0x05,
        0xB4,
        0x04,
        0x02,
        0x08,
        0x0A,
        0x61,
        0x8D,
        0x56,
        0x7B,
        0x00,
        0x00,
        0x00,
        0x00,
        0x01,
        0x03,
        0x03,
        0x07,
    ]

    ip_hdr = IPHeader.decode(bytes(raw))
    tcp_hdr = TCPHeader.decode(ip_hdr.payload)

    assert 0x1E22 == tcp_hdr.checksum(ip_hdr)
