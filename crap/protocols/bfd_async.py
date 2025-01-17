from __future__ import annotations

from scapy.data import ETH_P_IP  # type: ignore
from scapy.layers.inet import IP, UDP  # type: ignore
from scapy.packet import Raw  # type: ignore

from crap.protocols.l2 import build_l2
from crap.settings import Settings

from .base_header import BaseHeader


class BfdAsync(BaseHeader):
    def __init__(self: BfdAsync) -> None:
        self.data = (
            IP(
                src=Settings.IPV4_HOST1,
                dst=Settings.IPV4_HOST2,
                tos=Settings.DSCP,
            )
            / UDP(
                dport=Settings.BFD_ASYNC_DST_PORT,
                sport=Settings.BFD_ASYNC_SRC_PORT,
            )
            / Raw(load=bytearray(8))
        )

        self.set_filter(
            f" and ip"
            f" and src {Settings.IPV4_HOST1}"
            f" and dst {Settings.IPV4_HOST2}"
            f" and udp"
            f" and dst port {Settings.BFD_ASYNC_DST_PORT}"
            f" and src port {Settings.BFD_ASYNC_SRC_PORT}"
        )

        build_l2(
            dst=Settings.MAC_HOST2,
            eth2=True,
            etype=ETH_P_IP,
            header=self,
            src=Settings.MAC_HOST1,
        )

        self.build()
