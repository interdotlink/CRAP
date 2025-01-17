from __future__ import annotations

from scapy.data import ETH_P_IPV6  # type: ignore
from scapy.layers.inet6 import IPv6  # type: ignore
from scapy.layers.vrrp import VRRPv3  # type: ignore

from crap.protocols.l2 import build_l2
from crap.settings import Settings

from .base_header import BaseHeader


class VrrpV3(BaseHeader):
    def __init__(self: VrrpV3) -> None:
        self.data = IPv6(
            src=Settings.IPV6_HOST1,
            dst=Settings.IPV6_MC_VRRPV3,
            tc=Settings.DSCP,
        ) / VRRPv3(vrid=Settings.VRRP_VRID, addrlist=[Settings.IPV6_HOST3])

        SRC_MAC = Settings.MAC_VRRP_V4_VRID + f"{Settings.VRRP_VRID:02X}"

        self.set_filter(
            f" and ip6"
            f" and src {Settings.IPV6_HOST1}"
            f" and dst {Settings.IPV6_MC_VRRPV3}"
            f" and ip6 proto {Settings.IPV6_NH_VRRP}"
        )

        build_l2(
            dst=Settings.MAC_MC_VRRP,
            eth2=True,
            etype=ETH_P_IPV6,
            header=self,
            src=SRC_MAC,
        )

        self.build()
