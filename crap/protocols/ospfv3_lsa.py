from __future__ import annotations

from scapy.contrib.ospf import (  # type: ignore
    OSPFv3_Hdr,
    OSPFv3_Link,
    OSPFv3_LSUpd,
    OSPFv3_Network_LSA,
    OSPFv3_Router_LSA,
)
from scapy.data import ETH_P_IPV6  # type: ignore
from scapy.layers.inet6 import IPv6  # type: ignore

from crap.protocols.l2 import build_l2
from crap.settings import Settings

from .base_header import BaseHeader


class OspfV3Lsa(BaseHeader):
    def __init__(self: OspfV3Lsa) -> None:
        self.data = (
            IPv6(
                src=Settings.IPV6_HOST1_LL,
                dst=Settings.IPV6_MC_OSPF,
                hlim=1,
                tc=Settings.DSCP,
            )
            / OSPFv3_Hdr(
                src=Settings.IPV4_HOST1_LOOPBACK,
                type=Settings.OSPF_MESSAGE_UPDATE,
                instance=64,
            )
            / OSPFv3_LSUpd(
                lsalist=[
                    OSPFv3_Network_LSA(
                        adrouter=Settings.IPV4_HOST1_LOOPBACK,
                        reserved=0,
                        options=(
                            Settings.OSPF_OPTION_V6
                            | Settings.OSPF_OPTION_EXTERNAL
                            | Settings.OSPF_OPTION_ROUTER
                            | Settings.OSPF_OPTION_AF
                        ),
                    ),
                    OSPFv3_Router_LSA(
                        adrouter=Settings.IPV4_HOST1_LOOPBACK,
                        options=(
                            Settings.OSPF_OPTION_V6
                            | Settings.OSPF_OPTION_EXTERNAL
                            | Settings.OSPF_OPTION_ROUTER
                            | Settings.OSPF_OPTION_AF
                        ),
                        linklist=[
                            OSPFv3_Link(
                                intid=6,
                                neighintid=6,
                                neighbor=Settings.IPV4_HOST2_LOOPBACK,
                            )
                        ],
                    ),
                ]
            )
        )

        # Off-set to OSPF Message Type (zero indexed)
        self.set_filter(
            f" and proto ospf"
            f" and src {Settings.IPV6_HOST1_LL}"
            f" and dst {Settings.IPV6_MC_OSPF}"
            f" and ip6[{len(IPv6())+1}] == {Settings.OSPF_MESSAGE_UPDATE}"
        )

        build_l2(
            dst=Settings.MAC_MC_IPV6_OSPF,
            eth2=True,
            etype=ETH_P_IPV6,
            header=self,
            src=Settings.MAC_HOST1,
        )

        self.build()
