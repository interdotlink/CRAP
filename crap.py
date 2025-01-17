#!/usr/bin/env python3

from crap.cli_args import CliArgs
from crap.generator import Generator
from crap.settings import Settings
from crap.protocols import IcmpV4EchoRequest, IcmpV4EchoReply
from time import sleep


def main():
    CliArgs.parse_cli_args()

    print(
        f"Packet size: {len(Settings.FRAME.get_packet())}\n"
        f"Packet data: {Settings.FRAME.get_packet_string()}\n"
        f"Filter data: {Settings.FRAME.get_filter_stack()}\n"
    )

    if Settings.RX:
        if Settings.UNICAST:
            Generator.send_frames(IcmpV4EchoReply(), 1)
        Generator.receive_frames(Settings.FRAME)
    else:
        if Settings.UNICAST:
            Generator.send_frames(IcmpV4EchoRequest(), 1)
            sleep(1)  # Allow for MAC propagation before sending test frame
        Generator.send_frames(Settings.FRAME, Settings.PACKET_COUNT)


main()
