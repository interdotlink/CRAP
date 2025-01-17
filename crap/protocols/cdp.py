from __future__ import annotations

from crap.protocols.l2 import build_l2
from crap.settings import Settings

from .base_header import BaseHeader
from .llc import Llc
from .snap import Snap


class Cdp(BaseHeader):
    def __init__(self: Cdp) -> None:
        """
        No support in Scapy for CDP, copy bytes from a PCAP
        """
        self.data = bytes.fromhex(Settings.CDP_PAYLOAD)
        self.insert_at_bottom(
            Snap(code=Settings.CDP_CODE, oui=Settings.CDP_OUI)
        )
        self.insert_at_bottom(
            Llc(
                ctrl=Settings.CDP_CTRL,
                dsap=Settings.CDP_DSAP,
                ssap=Settings.CDP_SSAP,
            )
        )

        # Off-set to LLC protocol ID
        if Settings.VLAN:
            self.set_filter(
                f" and ether[24:2] = {hex(Settings.LLC_PROTO_ID_CDP)}"
            )
        else:
            self.set_filter(
                f" and ether[20:2] = {hex(Settings.LLC_PROTO_ID_CDP)}"
            )

        length = self.get_stack_length()
        build_l2(
            dst=Settings.MAC_MULTICAST,
            eth2=False,
            etype=length,
            header=self,
            src=Settings.MAC_HOST1,
        )

        self.build()
