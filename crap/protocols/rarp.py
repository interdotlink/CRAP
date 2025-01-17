from __future__ import annotations

from scapy.layers.l2 import ARP  # type: ignore
from scapy.packet import Padding  # type: ignore

from crap.protocols.l2 import build_l2
from crap.settings import Settings

from .base_header import BaseHeader


class Rarp(BaseHeader):
    def __init__(self: Rarp) -> None:
        self.data = ARP(
            psrc=Settings.IPV4_HOST2,
            hwsrc=Settings.MAC_HOST2,
            hwdst=Settings.MAC_HOST1,
            pdst=Settings.IPV4_HOST1,
            op=Settings.ARP_REPLY,
        )

        self.set_filter(f" and ether proto {hex(Settings.ETHERTYPE_RARP)}")

        build_l2(
            dst=Settings.MAC_HOST1,
            eth2=True,
            etype=Settings.ETHERTYPE_RARP,
            header=self,
            src=Settings.MAC_HOST2,
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
