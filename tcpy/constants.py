IFF_TUN = 0x0001  # tunnel IP packets
IFF_TAP = 0x0002  # tunnel ethernet frames
IFF_NO_PI = 0x1000  # don't pass extra packet info
IFF_ONE_QUEUE = 0x2000  # beats me ;)
TUNSETIFF = 0x400454CA

ETH_P_ARP = 0x0806  # Address Resolution packet
ETH_P_IP = 0x0800  # Internet Protocol packet

ARP_ETHERNET = 0x0001
ARP_IPV4 = 0x0800