from __future__ import annotations

from scapy.layers.l2 import SNAP  # type: ignore

from .base_header import BaseHeader


class Snap(BaseHeader):
    def __init__(self: BaseHeader, code: int, oui: int) -> None:
        self.data = SNAP(code=code, OUI=oui)
        self.set_filter("")
