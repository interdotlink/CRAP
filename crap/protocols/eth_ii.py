from __future__ import annotations

from scapy.layers.l2 import Ether  # type: ignore

from .base_header import BaseHeader


class EthII(BaseHeader):
    """
    Base class for all EthernetII frames
    """

    def __init__(self: EthII, dst: str, src: str, type: int) -> None:
        self.data = Ether(dst=dst, src=src, type=type)
        self.set_filter(f"ether src {src} and ether dst {dst}")
