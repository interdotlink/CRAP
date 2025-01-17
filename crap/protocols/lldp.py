from __future__ import annotations

from crap.protocols.l2 import build_l2
from crap.settings import Settings

from .base_header import BaseHeader


class Lldp(BaseHeader):
    def __init__(self: Lldp) -> None:
        """
        No support in Scapy for LLDP, copy bytes from a PCAP
        """
        self.data = bytes.fromhex(Settings.LLDP_PAYLOAD)
        self.set_filter(f" and ether proto {hex(Settings.ETHERTYPE_LLDP)}")

        build_l2(
            dst=Settings.MAC_LLDP,
            eth2=True,
            etype=Settings.ETHERTYPE_LLDP,
            header=self,
            src=Settings.MAC_HOST1,
        )

        self.build()
