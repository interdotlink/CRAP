from __future__ import annotations

from typing import Optional

from scapy.layers.l2 import Dot1Q  # type: ignore

from .base_header import BaseHeader


class Vlan(BaseHeader):
    def __init__(
        self: Vlan, id: Optional[int], prio: Optional[int], type: int
    ) -> None:
        if id == None:
            raise ValueError(
                f"VLAN ID must be int between 0 and 4094 inclusive, not {id}"
            )

        if prio == None:
            prio = 0

        self.data = Dot1Q(prio=prio, vlan=id, type=type)
        self.set_filter(f" and vlan {id}")
