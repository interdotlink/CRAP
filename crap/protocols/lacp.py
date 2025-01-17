from __future__ import annotations

from crap.protocols.l2 import build_l2
from crap.settings import Settings

from .base_header import BaseHeader
from .slow_protocols import SlowProtocols


class Lacp(BaseHeader):
    def __init__(self: Lacp) -> None:
        """
        No support in Scapy for LACP, copy bytes from a PCAP
        """
        self.data = bytes.fromhex(Settings.LACP_PAYLOAD)
        self.insert_at_bottom(SlowProtocols(type=Settings.SLOW_PROTOCOLS_LACP))

        # Off-set to Slow protocol type byte
        if Settings.QINQ and Settings.VLAN:
            self.set_filter(
                f" and ether[22] == {Settings.SLOW_PROTOCOLS_LACP}"
            )
        if Settings.VLAN:
            self.set_filter(
                f" and ether[18] == {Settings.SLOW_PROTOCOLS_LACP}"
            )
        else:
            self.set_filter(
                f" and ether[14] == {Settings.SLOW_PROTOCOLS_LACP}"
            )

        build_l2(
            dst=Settings.MAC_SLOW_PROTOCOLS,
            eth2=True,
            etype=Settings.ETHERTYPE_SLOW_PROTOCOLS,
            header=self,
            src=Settings.MAC_HOST1,
        )

        self.build()
