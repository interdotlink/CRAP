from __future__ import annotations

from scapy.data import ETH_P_IP  # type: ignore
from scapy.layers.inet import ICMP, IP  # type: ignore

from crap.protocols.l2 import build_l2
from crap.settings import Settings

from .base_header import BaseHeader


class IcmpV4EchoRequest(BaseHeader):
    def __init__(self: IcmpV4EchoRequest) -> None:
        self.data = (
            IP(
                src=Settings.IPV4_HOST1,
                dst=Settings.IPV4_HOST2,
                tos=Settings.DSCP,
            )
            / ICMP(type="echo-request", seq=1)
            / (
                b"A" * 64
            )  # Pad ICMP payload to ensure we achieve minimum packet size
        )

        self.set_filter(
            f" and ip"
            f" and src {Settings.IPV4_HOST1}"
            f" and dst {Settings.IPV4_HOST2}"
            f" and icmp and icmp[icmptype] == icmp-echo"
        )

        build_l2(
            dst=Settings.MAC_HOST2,
            eth2=True,
            etype=ETH_P_IP,
            header=self,
            src=Settings.MAC_HOST1,
        )

        self.build()
