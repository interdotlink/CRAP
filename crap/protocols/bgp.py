from __future__ import annotations

from scapy.data import ETH_P_IP  # type: ignore
from scapy.layers.inet import IP, TCP  # type: ignore

"""
Importing the Scapy BGP module, a warning is logged which is irrelevant
to this tool. Temporarily suppress scapy warnings.
"""

import logging

scapy_log_level = logging.getLogger("scapy.runtime").level
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.contrib.bgp import BGP, BGPKeepAlive  # type: ignore

logging.getLogger("scapy.runtime").setLevel(scapy_log_level)

from crap.protocols.l2 import build_l2
from crap.settings import Settings

from .base_header import BaseHeader


class Bgp(BaseHeader):
    def __init__(self: Bgp) -> None:
        self.data = (
            IP(
                src=Settings.IPV4_HOST1,
                dst=Settings.IPV4_HOST2,
                tos=Settings.DSCP,
            )
            / TCP(
                dport=Settings.BGP_DST_PORT,
                sport=Settings.BGP_SRC_PORT,
                flags=0x8,  # PUSH
            )
            / BGP()
            / BGPKeepAlive()
        )

        self.set_filter(
            f" and ip"
            f" and src {Settings.IPV4_HOST1}"
            f" and dst {Settings.IPV4_HOST2}"
            f" and tcp"
            f" and dst port {Settings.BGP_DST_PORT}"
            f" and src port {Settings.BGP_SRC_PORT}"
        )

        build_l2(
            dst=Settings.MAC_HOST2,
            eth2=True,
            etype=ETH_P_IP,
            header=self,
            src=Settings.MAC_HOST1,
        )

        self.build()
