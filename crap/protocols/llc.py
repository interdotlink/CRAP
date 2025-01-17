from __future__ import annotations

from scapy.layers.l2 import LLC  # type: ignore

from crap.settings import Settings

from .base_header import BaseHeader


class Llc(BaseHeader):
    def __init__(self: BaseHeader, ctrl: int, dsap: int, ssap: int) -> None:
        self.data = LLC(ctrl=ctrl, dsap=dsap, ssap=ssap)
        self.set_filter(" and llc")
        if ctrl == Settings.CDP_CTRL:
            self.filter += " ui"
