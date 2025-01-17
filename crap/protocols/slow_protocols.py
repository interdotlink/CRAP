from __future__ import annotations

import sys

from crap.settings import Settings

from .base_header import BaseHeader


class SlowProtocols(BaseHeader):
    def __init__(self: BaseHeader, type: int) -> None:
        self.data = type.to_bytes(1, sys.byteorder)
        self.set_filter(
            f" and ether proto {hex(Settings.ETHERTYPE_SLOW_PROTOCOLS)}"
        )
