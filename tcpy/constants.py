from enum import Enum

IFF_TUN = 0x0001  # tunnel IP packets
IFF_TAP = 0x0002  # tunnel ethernet frames
IFF_NO_PI = 0x1000  # don't pass extra packet info
IFF_ONE_QUEUE = 0x2000  # beats me ;)
TUNSETIFF = 0x400454CA

ETH_P_ARP = 0x0806  # Address Resolution packet
ETH_P_IP = 0x0800  # Internet Protocol packet

ARP_ETHERNET = 0x0001
ARP_IPV4 = 0x0800

ARP_REQUEST = 0x0001
ARP_REPLY = 0x0002

ICMP = 0x01
IPV4 = 0x04
IP_TCP = 0x06

ICMP_V4_REPLY = 0x00
ICMP_V4_ECHO = 0x08

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10

SocketState = Enum(
    "SocketState",
    [
        "UNCONNECTED",  # Not connected to a socket yet
        "CONNECTING",
        "CONNECTED",
        "DISCONNECTING",
    ],
)

TCPState = Enum(
    "TCPState",
    [
        "LISTEN",  # Waiting for a connection request
        "SYN_SENT",  # Sent a connection request, waiting for ack
        "SYN_RECV",  # Received a connection request, sent ack, waiting for final ack in 3 way handshake
        "ESTABLISHED",  # connection established
        "FIN_WAIT_1",  # our side has shutdown, waiting to complete transmission of remaining buffered data
        "FIN_WAIT_2",  # all buffered data sent, waiting for remote to shutdown
        "CLOSE",  # socket is finished
        "CLOSE_WAIT",  # remote side has shutdown and is waiting for us to finish writing our data and to shutdown
        "CLOSING",  # both sides have shutdown but we still have data we have to finish sending
        "LAST_ACK",  # our side has shutdown after remote has shutdown, there may still be data in our buffer that we have to finish sending
        "TIME_WAIT",  # timeout to catch resent junk before entering closed, can only be entered from FIN_WAIT_2 or CLOSING, this is required because the other end may not have gotten our last ACK causing it to retransmit the data packet
    ],
)
