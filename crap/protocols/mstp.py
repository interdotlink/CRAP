from __future__ import annotations

from scapy.layers.l2 import LLC, STP  # type: ignore
from scapy.packet import Padding  # type: ignore

from crap.protocols.l2 import build_l2
from crap.settings import Settings

from .base_header import BaseHeader
from .llc import Llc


class Mstp(BaseHeader):
    def __init__(self: Mstp) -> None:
        """
        No support in Scapy for LACP, copy bytes from a PCAP
        """
        self.data = bytes.fromhex(Settings.MSTP_PAYLOAD)

        self.insert_at_bottom(
            Llc(
                ctrl=Settings.STP_CTRL,
                dsap=Settings.STP_DSAP,
                ssap=Settings.STP_SSAP,
            )
        )

        """
        Match on STP protocol version, no explicit support in libpcacp for MSTP.
        """
        if Settings.VLAN:
            self.set_filter(" and ether proto \stp and ether[19:1] == 0x3")
        else:
            self.set_filter(
                " and ether proto \stp and ether[19:1] == 0x3 and not vlan"
            )

        length = self.get_stack_length()
        build_l2(
            dst=Settings.MAC_MSTP,
            eth2=False,
            etype=length,
            header=self,
            src=Settings.MAC_HOST1,
        )

        self.build()
