from __future__ import annotations

from scapy.data import ETH_P_IP  # type: ignore
from scapy.layers.inet import IP  # type: ignore
from scapy.layers.vrrp import VRRP  # type: ignore

from crap.protocols.l2 import build_l2
from crap.settings import Settings

from .base_header import BaseHeader


class VrrpV2(BaseHeader):
    def __init__(self: VrrpV2) -> None:
        self.data = IP(
            src=Settings.IPV4_HOST1,
            dst=Settings.IPV4_MC_VRRP,
            tos=Settings.DSCP,
        ) / VRRP(vrid=Settings.VRRP_VRID, addrlist=[Settings.IPV4_HOST3])

        SRC_MAC = Settings.MAC_VRRP_V4_VRID + f"{Settings.VRRP_VRID:02X}"

        self.set_filter(
            f" and ip"
            f" and src {Settings.IPV4_HOST1}"
            f" and dst {Settings.IPV4_MC_VRRP}"
            f" and ip proto {Settings.IPV4_PROTO_VRRP}"
        )

        build_l2(
            dst=Settings.MAC_MC_VRRP,
            eth2=True,
            etype=ETH_P_IP,
            header=self,
            src=SRC_MAC,
        )

        self.build()
