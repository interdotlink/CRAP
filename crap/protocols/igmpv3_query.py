from __future__ import annotations

from scapy.contrib.igmpv3 import IGMPv3, IGMPv3mq  # type: ignore
from scapy.data import ETH_P_IP  # type: ignore
from scapy.layers.inet import IP, IPOption_Router_Alert  # type: ignore
from scapy.packet import Padding  # type: ignore

from crap.protocols.l2 import build_l2
from crap.settings import Settings

from .base_header import BaseHeader


class IgmpV3Query(BaseHeader):
    def __init__(self: IgmpV3Query) -> None:
        """
        QRV: https://www.rfc-editor.org/rfc/rfc3376#section-8.1
        QQIC: https://www.rfc-editor.org/rfc/rfc3376#section-4.1.7
        """
        self.data = (
            IP(
                tos=Settings.DSCP,
                flags=2,
                ttl=1,
                src=Settings.IPV4_HOST1,
                dst=Settings.IPV4_MC_ALL_HOST,
                options=[IPOption_Router_Alert()],
            )
            / IGMPv3()
            / IGMPv3mq(qrv=2, qqic=20)
        )

        # Off-set to IGMP message type
        self.set_filter(
            f" and ip"
            f" and src {Settings.IPV4_HOST1}"
            f" and dst {Settings.IPV4_MC_ALL_HOST}"
            f" and igmp and igmp[0] == 0x11"
        )

        build_l2(
            dst=Settings.MAC_MC_IPV4_ALL_NODES,
            eth2=True,
            etype=ETH_P_IP,
            header=self,
            src=Settings.MAC_HOST1,
        )

        self.build()

        # Pad to minimum Ethernet frame size
        if Settings.PADDING:
            if len(self.data_stack) < 64:
                padding = Padding()
                padding.load = '\x00' * (64 - len(self.data_stack))
                self.data = self.data / padding
                # Rebuild to incorporate padding
                self.build()
