from __future__ import annotations

from scapy.data import ETH_P_IPV6  # type: ignore
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6  # type: ignore

from crap.protocols.l2 import build_l2
from crap.settings import Settings

from .base_header import BaseHeader


class MulticastV6(BaseHeader):
    def __init__(self: MulticastV6) -> None:
        self.data = (
            IPv6(
                src=Settings.IPV6_HOST1_LL,
                dst=Settings.IPV6_MC_ALL_NODES,
                hlim=1,
                tc=Settings.DSCP,
            )
            / ICMPv6EchoRequest(seq=1)
            / (
                b"A" * 64
            )  # Pad ICMP payload to ensure we achieve minimum packet size
        )

        self.set_filter(
            f" and ip6"
            f" and src {Settings.IPV6_HOST1_LL}"
            f" and dst {Settings.IPV6_MC_ALL_NODES}"
            f" and icmp6 and ip6[{len(IPv6())}] == {Settings.ICMPV6_TYPE_ECHO_REQ}"
        )

        build_l2(
            dst=Settings.MAC_MC_IPV6_ALL_NODES,
            eth2=True,
            etype=ETH_P_IPV6,
            header=self,
            src=Settings.MAC_HOST1,
        )

        self.build()
