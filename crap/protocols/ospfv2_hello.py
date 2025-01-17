from __future__ import annotations

from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello  # type: ignore
from scapy.data import ETH_P_IP  # type: ignore
from scapy.layers.inet import IP  # type: ignore

from crap.protocols.l2 import build_l2
from crap.settings import Settings

from .base_header import BaseHeader


class OspfV2Hello(BaseHeader):
    def __init__(self: OspfV2Hello) -> None:
        self.data = (
            IP(
                src=Settings.IPV4_HOST1,
                dst=Settings.IPV4_MC_OSPF,
                ttl=1,
                tos=Settings.DSCP,
            )
            / OSPF_Hdr(src=Settings.IPV4_HOST1_LOOPBACK)
            / OSPF_Hello(
                mask=Settings.IPV4_MASK,
                router=Settings.IPV4_HOST1,
                backup=Settings.IPV4_HOST2,
                options=Settings.OSPF_OPTION_EXTERNAL,
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
            f" and ip[{len(IP())+1}] == {Settings.OSPF_MESSAGE_HELLO}"
        )

        build_l2(
            dst=Settings.MAC_MC_IPV4_OSPF,
            eth2=True,
            etype=ETH_P_IP,
            header=self,
            src=Settings.MAC_HOST1,
        )

        self.build()
