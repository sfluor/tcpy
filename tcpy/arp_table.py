import array
from typing import Dict, Optional, Tuple

from .arp import ARPHeader, ARPIPv4
from .constants import ARP_IPV4, ARP_REPLY, ETH_P_ARP
from .eth import EthernetHeader
from .ip_util import int2ip


class ARPTable:

    """An ARPTable (stores and resolves (protocol, protocol address) pairs to mac addresses)"""

    def __init__(self, ip: str, mac: str):
        # TODO limit entries ?
        """Creates a new ARP Table

        :ip: test ip string (str)
        :mac: test mac address (str)
        """
        self._h: Dict[Tuple[int, str], str] = {}
        self._ip = ip
        self._mac = mac

    def process_arp(self, eth: EthernetHeader) -> EthernetHeader:
        """processes the given ethernet packet (throws an exception if it's not an arp packet)

        :eth: An EthernetHeader instance
        :return: An EthernetHeader containing the reply
        """

        arp = eth.arp_hdr()
        if not arp.is_supported():
            print("Unsupported layer type")

        ipv4 = arp.ipv4_data()

        merge = self.update(arp.protype, ipv4.sip, ipv4.smac)
        if not merge:
            self.insert(arp.protype, ipv4.sip, ipv4.smac)

        # ARP_REQUEST, let's answer
        if arp.is_arp_request():
            return self._reply(arp, ipv4)

        return None

    def _reply(self, arp: "ARPHeader", ipv4: "ARPIPv4") -> EthernetHeader:
        """reply to an arp request

        :arp: An ARPHeader instance
        :ipv4: An ARPIPv4 instance
        :return: An EthernetHeader containing the reply

        """
        data = ipv4
        data.dmac = data.smac
        data.dip = data.sip
        data.smac = array.array(
            "B", [int(x, 16) for x in self._mac.split(":")]
        ).tobytes()
        data.sip = self._ip

        arp.opcode = ARP_REPLY
        arp.replace_data(ipv4.encode())
        return EthernetHeader(
            dmac=data.dmac, smac=data.smac, typ=ETH_P_ARP, payload=arp.encode()
        )

    def update(self, protype: int, pro_addr: str, mac: str) -> bool:
        """updates the given entry only if it already exists
        it also returns a boolean indicating if yes or no the
        entry was updated

        :protype: the protocol type (int)
        :pro_addr: the protocol address (str)
        :mac: the mac address (str)
        :returns: a boolean indicating if the entry was updated

        """

        key = (protype, pro_addr)
        if key in self._h:
            self._h[key] = mac
            return True

        return False

    def insert(self, protype: int, pro_addr: str, mac: str) -> None:
        """inserts the given entry in the table

        :protype: the protocol type (int)
        :pro_addr: the protocol address (str)
        :mac: the mac address (str)

        """
        self._h[(protype, pro_addr)] = mac

    def get_mac_for_ip(self, ip: int) -> Optional[str]:
        """resolves an IP address to a mac address

        :ip: the IP address to resolve to a mac address in int format
        :returns: a mac address in string format or None if not found

        """
        return self._h.get((ARP_IPV4, int2ip(ip)), None)
