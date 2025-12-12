from __future__ import annotations

from scapy.layers.l2 import LLC, STP  # type: ignore
from scapy.packet import Padding  # type: ignore

from crap.protocols.l2 import build_l2
from crap.settings import Settings

from .base_header import BaseHeader


class Rstp(BaseHeader):
    def __init__(self: Rstp) -> None:
        self.data = LLC() / STP(
            version=Settings.RSTP_STP_VERSION,
            bpdutype=Settings.RSTP_BPDU_TYPE,
            bpduflags=Settings.RSTP_FLAGS,
            rootmac=Settings.MAC_HOST1,
            rootid=Settings.RSTP_ROOT_ID,
            bridgemac=Settings.MAC_HOST1,
            bridgeid=Settings.RSTP_BRDIGE_ID,
            portid=Settings.RSTP_PORT_ID,
            age=Settings.RSTP_BPDU_AGE,
        )

        """
        Scapy is missing the final version & length byte for an RSTP header
        Luckily it can be a single byte of value 0x0.
        """
        self.data.add_payload(bytes.fromhex("00"))

        """
        Pad the frame to be 64 bytes so that the length of the Ieee802
        header is at least 64
        """
        if Settings.PADDING:
            padding = Padding()
            padding.load = '\x00' * (64 - len(self.data))
            self.data = self.data / padding

        """
        Match on BPDU version, no explicit support in libpcacp for RSTP.
        """
        if Settings.VLAN:
            self.set_filter(" and ether proto \stp and ether[20:1] == 0x2")
        else:
            self.set_filter(
                " and ether proto \stp and ether[20:1] == 0x2 and not vlan"
            )

        length = self.get_stack_length()
        build_l2(
            dst=Settings.MAC_RSTP,
            eth2=False,
            etype=length,
            header=self,
            src=Settings.MAC_HOST1,
        )

        self.build()
