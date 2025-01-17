import socket
import typing

from scapy.sendrecv import sendp, sniff  # type: ignore
from scapy.utils import wrpcap  # type: ignore

from crap.protocols import BaseHeader, Bgp
from crap.settings import Settings


class Generator:
    @staticmethod
    def receive_frames(frame: BaseHeader) -> None:
        filter = frame.get_filter_stack()
        if filter:
            print(f"Starting capture using filter: {filter}")
            frames = sniff(
                count=Settings.PACKET_COUNT,
                iface=Settings.INTERFACE,
                filter=filter,
            )
        else:
            print("Starting capture without filter")
            frames = sniff(
                count=Settings.PACKET_COUNT, iface=Settings.INTERFACE
            )

        print(f"Captured {len(frames)} frames")

        if Settings.PCAP:
            wrpcap(Settings.PCAP, frames)

    @staticmethod
    def send_frames(frame: BaseHeader, count: int) -> None:
        frames = [frame.get_packet() for i in range(1, count + 1)]

        if Settings.PCAP:
            wrpcap(Settings.PCAP, frames)

        """
        If sending TCP packets, we need to use a raw socket,
        otherwise the Kernel will try to start a 3-way handshake first.
        """
        if isinstance(frame, Bgp):
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            s.bind((Settings.INTERFACE, 0))
            for i in range(1, count + 1):
                s.send(bytes(frame.get_packet()))
            print(f"Sent {count} packets.")
        else:
            sendp(x=frames, iface=Settings.INTERFACE)
