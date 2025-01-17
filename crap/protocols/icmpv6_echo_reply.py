from __future__ import annotations

from scapy.data import ETH_P_IPV6  # type: ignore
from scapy.layers.inet6 import ICMPv6EchoReply, IPv6  # type: ignore

from crap.protocols.l2 import build_l2
from crap.settings import Settings

from .base_header import BaseHeader


class IcmpV6EchoReply(BaseHeader):
    def __init__(self: IcmpV6EchoReply) -> None:
        self.data = (
            IPv6(
                src=Settings.IPV6_HOST2,
                dst=Settings.IPV6_HOST1,
                tc=Settings.DSCP,
            )
            / ICMPv6EchoReply()
            / (
                b"A" * 64
            )  # Pad ICMP payload to ensure we achieve minimum packet size
        )

        # Byte off-set to ICMPv6 type field:
        self.set_filter(
            f" and ip6"
            f" and src {Settings.IPV6_HOST2}"
            f" and dst {Settings.IPV6_HOST1}"
            f" and icmp6 and ip6[40] == 129"
        )

        build_l2(
            dst=Settings.MAC_HOST1,
            eth2=True,
            etype=ETH_P_IPV6,
            header=self,
            src=Settings.MAC_HOST2,
        )

        self.build()
