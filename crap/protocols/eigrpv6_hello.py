from __future__ import annotations

from scapy.contrib.eigrp import EIGRP, EIGRPParam, EIGRPSwVer  # type: ignore
from scapy.data import ETH_P_IPV6  # type: ignore
from scapy.layers.inet6 import IPv6  # type: ignore

from crap.protocols.l2 import build_l2
from crap.settings import Settings

from .base_header import BaseHeader


class EigrpV6Hello(BaseHeader):
    def __init__(self: EigrpV6Hello) -> None:
        self.data = IPv6(
            src=Settings.IPV6_HOST1,
            dst=Settings.IPV6_MC_EIGRP,
            tc=Settings.DSCP,
        ) / EIGRP(tlvlist=[EIGRPParam(), EIGRPSwVer()])

        self.set_filter(
            f" and ip6"
            f" and src {Settings.IPV6_HOST1}"
            f" and dst {Settings.IPV6_MC_EIGRP}"
            f" and ip6 proto {Settings.IPV6_NH_EIGRP}"
        )

        build_l2(
            dst=Settings.MAC_MC_IPV6_EIGRP,
            eth2=True,
            etype=ETH_P_IPV6,
            header=self,
            src=Settings.MAC_HOST1,
        )

        self.build()
