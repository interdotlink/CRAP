from __future__ import annotations

from scapy.layers.l2 import LLC, STP  # type: ignore
from scapy.packet import Padding  # type: ignore

from crap.protocols.l2 import build_l2
from crap.settings import Settings

from .base_header import BaseHeader


class Stp(BaseHeader):
    def __init__(self: Stp) -> None:
        self.data = LLC() / STP(
            rootmac=Settings.MAC_HOST1,
            rootid=Settings.STP_ROOT_ID,
            bridgemac=Settings.MAC_HOST1,
            bridgeid=Settings.STP_BRDIGE_ID,
            portid=Settings.STP_PORT_ID,
            age=Settings.STP_AGE,
        )

        """
        Pad the STP frame to be 64 bytes so that the length of the Ieee802
        header is at least 64
        """
        if Settings.PADDING:
            padding = Padding()
            padding.load = '\x00' * (64 - len(self.data))
            self.data = self.data / padding

        self.set_filter(" and ether proto \stp")

        length = self.get_stack_length()
        build_l2(
            dst=Settings.MAC_STP,
            eth2=False,
            etype=length,
            header=self,
            src=Settings.MAC_HOST1,
        )

        self.build()
