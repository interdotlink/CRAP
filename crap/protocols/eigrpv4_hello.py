from __future__ import annotations

from scapy.contrib.eigrp import EIGRP, EIGRPParam, EIGRPSwVer  # type: ignore
from scapy.data import ETH_P_IP  # type: ignore
from scapy.layers.inet import IP  # type: ignore

from crap.protocols.l2 import build_l2
from crap.settings import Settings

from .base_header import BaseHeader


class EigrpV4Hello(BaseHeader):
    def __init__(self: EigrpV4Hello) -> None:
        self.data = IP(
            src=Settings.IPV4_HOST1,
            dst=Settings.IPV4_MC_EIGRP,
            ttl=2,
            tos=Settings.DSCP,
        ) / EIGRP(tlvlist=[EIGRPParam(), EIGRPSwVer()])

        self.set_filter(
            f" and ip"
            f" and src {Settings.IPV4_HOST1}"
            f" and dst {Settings.IPV4_MC_EIGRP}"
            f" and ip proto {Settings.IPV4_PROTO_EIGRP}"
        )

        build_l2(
            dst=Settings.MAC_MC_IPV4_EIGRP,
            eth2=True,
            etype=ETH_P_IP,
            header=self,
            src=Settings.MAC_HOST1,
        )

        self.build()
