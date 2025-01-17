from __future__ import annotations

from scapy.contrib.ospf import (  # type: ignore
    OSPF_Hdr,
    OSPF_Link,
    OSPF_LSUpd,
    OSPF_Router_LSA,
)
from scapy.data import ETH_P_IP  # type: ignore
from scapy.layers.inet import IP  # type: ignore

from crap.protocols.l2 import build_l2
from crap.settings import Settings

from .base_header import BaseHeader


class OspfV2Lsa(BaseHeader):
    def __init__(self: OspfV2Lsa) -> None:
        self.data = (
            IP(
                src=Settings.IPV4_HOST1,
                dst=Settings.IPV4_MC_OSPF,
                ttl=1,
                tos=Settings.DSCP,
            )
            / OSPF_Hdr(
                src=Settings.IPV4_HOST1_LOOPBACK,
                type=Settings.OSPF_MESSAGE_UPDATE,
            )
            / OSPF_LSUpd(
                lsalist=[
                    OSPF_Router_LSA(
                        age=3600,
                        id=Settings.IPV4_HOST1_LOOPBACK,
                        adrouter=Settings.IPV4_HOST1_LOOPBACK,
                        linklist=[
                            OSPF_Link(
                                id=Settings.IPV4_SUBNET,
                                data=Settings.IPV4_MASK,
                                type="stub",
                                metric=1,
                            )
                        ],
                    )
                ]
            )
        )

        """
        The off-set is to the OSPF message type to check for a hello message.
        This is the off-set -1 byte, because it's zero indexed.
        """
        self.set_filter(
            f" and proto ospf"
            f" and src {Settings.IPV4_HOST1}"
            f" and dst {Settings.IPV4_MC_OSPF}"
            f" and ip[{len(IP())+1}] == {Settings.OSPF_MESSAGE_UPDATE}"
        )

        build_l2(
            dst=Settings.MAC_MC_IPV4_OSPF,
            eth2=True,
            etype=ETH_P_IP,
            header=self,
            src=Settings.MAC_HOST1,
        )

        self.build()
