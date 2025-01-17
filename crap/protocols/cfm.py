from __future__ import annotations

from crap.protocols.l2 import build_l2
from crap.settings import Settings

from .base_header import BaseHeader


class Cfm(BaseHeader):
    def __init__(self: Cfm) -> None:
        """
        No support in Scapy for LLDP, copy bytes from a PCAP
        """
        self.data = bytes.fromhex(Settings.CFM_PAYLOAD)
        self.set_filter(f" and ether proto {hex(Settings.ETHERTYPE_CFM)}")

        build_l2(
            dst=Settings.MAC_CFM,
            eth2=True,
            etype=Settings.ETHERTYPE_CFM,
            header=self,
            src=Settings.MAC_HOST1,
        )

        self.build()
