from __future__ import annotations

from scapy.layers.l2 import Dot3  # type: ignore

from .base_header import BaseHeader


class Ieee8023(BaseHeader):
    """
    Base class for all IEEE 802.3 frames
    """

    def __init__(self: Ieee8023, dst: str, src: str, length) -> None:
        self.data = Dot3(dst=dst, len=length, src=src)
        self.set_filter(f"ether src {src} and ether dst {dst}")
