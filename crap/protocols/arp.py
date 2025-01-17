from __future__ import annotations

from scapy.data import ETH_P_ARP  # type: ignore
from scapy.layers.l2 import ARP  # type: ignore
from scapy.packet import Padding  # type: ignore

from crap.protocols.l2 import build_l2
from crap.settings import Settings

from .base_header import BaseHeader


class Arp(BaseHeader):
    def __init__(self: Arp) -> None:
        self.data = ARP(
            psrc=Settings.IPV4_HOST1,
            hwsrc=Settings.MAC_HOST1,
            hwdst=Settings.MAC_ZEROS,
            pdst=Settings.IPV4_HOST2,
            op=Settings.ARP_REQUEST,
        )

        self.set_filter(f" and ether proto 0x{ETH_P_ARP:04x}")

        build_l2(
            dst=Settings.MAC_BROADCAST,
            eth2=True,
            etype=ETH_P_ARP,
            header=self,
            src=Settings.MAC_HOST1,
        )

        self.build()

        # Pad to minimum Ethernet frame size
        if Settings.PADDING:
            if len(self.data_stack) < 64:
                padding = Padding()
                padding.load = '\x00' * (64 - len(self.data_stack))
                self.data = self.data / padding
                # Rebuild to incorporate padding
                self.build()
