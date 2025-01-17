from __future__ import annotations

from scapy.contrib.isis import (  # type: ignore
    ISIS_AreaEntry,
    ISIS_AreaTlv,
    ISIS_CommonHdr,
    ISIS_IpInterfaceAddressTlv,
    ISIS_P2P_Hello,
    ISIS_P2PAdjacencyStateTlv,
    ISIS_PaddingTlv,
    ISIS_ProtocolsSupportedTlv,
)

from crap.protocols.l2 import build_l2
from crap.settings import Settings

from .base_header import BaseHeader
from .llc import Llc


class IsIsL1Hello(BaseHeader):
    def __init__(self: IsIsL1Hello) -> None:
        """
        Pad the HELLO so that the frame is at least 64 bytes, by adding Padding TLVs.
        This is different to other packets in CRAP because untagged ISIS uses Ieee802 frames and not EthII frames.
        """
        if Settings.PADDING:
            padding_tlvs = [
                ISIS_PaddingTlv(),
                ISIS_PaddingTlv(),
                ISIS_PaddingTlv(),
                ISIS_PaddingTlv(),
                ISIS_PaddingTlv(),
                ISIS_PaddingTlv(),
                ISIS_PaddingTlv(),
                ISIS_PaddingTlv(),
                ISIS_PaddingTlv(),
                ISIS_PaddingTlv(),
                ISIS_PaddingTlv(),
                ISIS_PaddingTlv(),
            ]
        else:
            padding_tlvs = []

        self.data = ISIS_CommonHdr() / ISIS_P2P_Hello(
            circuittype="L1",
            sourceid="0101.0101.0101",
            tlvs=[
                ISIS_P2PAdjacencyStateTlv(len=1),
                ISIS_ProtocolsSupportedTlv(),
                ISIS_AreaTlv(
                    areas=[ISIS_AreaEntry(areaid=Settings.ISIS_AREA_ID)]
                ),
                ISIS_IpInterfaceAddressTlv(addresses=[Settings.IPV4_HOST1]),
            ]
            + padding_tlvs,
        )

        self.insert_at_bottom(
            Llc(
                ctrl=Settings.ISIS_CONTROL,
                dsap=Settings.ISIS_DSAP,
                ssap=Settings.ISIS_SSAP,
            )
        )

        # Off-set to ISO PDU type byte
        if Settings.QINQ and Settings.VLAN:
            self.set_filter(
                f" and isis and ether[29] == {Settings.ISIS_PDU_P2P_HELLO}"
            )
        elif Settings.VLAN:
            self.set_filter(
                f" and isis and ether[25] == {Settings.ISIS_PDU_P2P_HELLO}"
            )
        else:
            self.set_filter(
                f" and isis and ether[21] == {Settings.ISIS_PDU_P2P_HELLO}"
            )

        length = self.get_stack_length()
        build_l2(
            dst=Settings.MAC_ISIS_L1,
            eth2=False,
            etype=length,
            header=self,
            src=Settings.MAC_HOST1,
        )

        self.build()
