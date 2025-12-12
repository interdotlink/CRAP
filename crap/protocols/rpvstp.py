from __future__ import annotations

from scapy.layers.l2 import STP  # type: ignore

from crap.protocols.l2 import build_l2
from crap.settings import Settings

from .base_header import BaseHeader
from .llc import Llc
from .snap import Snap


class Rpvstp(BaseHeader):
    def __init__(self: Rpvstp) -> None:
        self.data = STP(
            version=Settings.RPVSTP_STP_VERSION,
            bpdutype=Settings.RPVSTP_BPDU_TYPE,
            bpduflags=Settings.RPVSTP_FLAGS,
            rootmac=Settings.MAC_HOST1,
            rootid=Settings.RPVSTP_ROOT_ID,
            bridgemac=Settings.MAC_HOST1,
            bridgeid=Settings.RPVSTP_BRDIGE_ID,
            portid=Settings.RPVSTP_PORT_ID,
            age=Settings.RPVSTP_BPDU_AGE,
        )

        """
        No support in Scapy for RPVSTP. Add the TLV details manually.

        If a VLAN ID is being used, we need to re-write the last byte the
        the VLAN originating TLV to match the VLAN ID.
        """
        if Settings.VLAN:
            origin_tlv = (
                Settings.RPVSTP_TLV_ORIGIN[:-2] + f"{Settings.VLAN:02X}"
            )
        else:
            origin_tlv = Settings.RPVSTP_TLV_ORIGIN
        self.data.add_payload(
            bytes.fromhex(Settings.RPVSTP_TLV_LENGTH)
            + bytes.fromhex(origin_tlv)
        )

        self.insert_at_bottom(
            Snap(code=Settings.RPVSTP_CODE, oui=Settings.RPVSTP_OUI)
        )
        self.insert_at_bottom(
            Llc(
                ctrl=Settings.STP_CTRL,
                dsap=Settings.RPVSTP_DSAP,
                ssap=Settings.RPVSTP_SSAP,
            )
        )

        """
        Off-set to LLC protocol ID
        """
        if Settings.VLAN:
            self.set_filter(
                f" and ether[20:2] = {hex(Settings.LLC_PROTO_ID_RPVSTP)}"
            )
        else:
            self.set_filter(
                f" and ether[20:2] = {hex(Settings.LLC_PROTO_ID_RPVSTP)} and not vlan"
            )

        length = self.get_stack_length()
        build_l2(
            dst=Settings.MAC_RPVSTP,
            eth2=False,
            etype=length,
            header=self,
            src=Settings.MAC_HOST1,
        )

        self.build()
