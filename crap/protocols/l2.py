from crap.settings import Settings

from .base_header import BaseHeader
from .eth_ii import EthII
from .ieee8023 import Ieee8023
from .vlan import Vlan


def build_l2(
    dst: str, eth2: bool, etype: int, header: BaseHeader, src: str
) -> None:
    """
    Build and insert the Ethernet + VLAN headers
    """
    if Settings.QINQ != None and Settings.VLAN != None:
        header.insert_at_bottom(
            Vlan(prio=Settings.COS, id=Settings.QINQ, type=etype)
        )

        header.insert_at_bottom(
            Vlan(
                prio=Settings.COS,
                id=Settings.VLAN,
                type=Settings.ETHERTYPE_VLAN,
            )
        )

        header.insert_at_bottom(
            EthII(
                dst=dst,
                src=src,
                type=Settings.ETHERTYPE_VLAN,
            )
        )
    elif Settings.VLAN != None:
        header.insert_at_bottom(
            Vlan(prio=Settings.COS, id=Settings.VLAN, type=etype)
        )
        header.insert_at_bottom(
            EthII(
                dst=dst,
                src=src,
                type=Settings.ETHERTYPE_VLAN,
            )
        )
    else:
        if eth2:
            header.insert_at_bottom(
                EthII(
                    dst=dst,
                    src=src,
                    type=etype,
                )
            )
        else:
            header.insert_at_bottom(
                Ieee8023(
                    dst=dst,
                    src=src,
                    length=etype,
                )
            )
