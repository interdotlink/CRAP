from __future__ import annotations

import argparse
from typing import Any

from crap.protocols import *
from crap.settings import Settings


class CliArg:
    cli_arg: str
    desc: str
    hdr: BaseHeader

    def __init__(
        self: CliArg,
        cli_arg: str,
        desc: str,
        hdr: BaseHeader,
    ) -> None:
        self.cli_arg = cli_arg
        self.desc = desc
        self.hdr = hdr


class CliArgs:
    frame_types: dict[str, CliArg] = {}

    @staticmethod
    def __contains__(arg_name: str) -> bool:
        return arg_name in CliArgs.frame_types

    @staticmethod
    def get_frame_from_args(args: dict) -> BaseHeader:
        for frame_type in CliArgs.frame_types.keys():
            if args[frame_type]:
                return CliArgs.frame_types[frame_type].hdr
        raise ValueError(f"Unable to get frame header from CLI args: {args}")

    @staticmethod
    def generate_frame_args() -> None:
        CliArgs.frame_types["l2_arp"] = CliArg(
            cli_arg="--l2-arp", desc="ARP request", hdr=Arp()
        )
        CliArgs.frame_types["l2_cdp"] = CliArg(
            cli_arg="--l2-cdp", desc="CDP message", hdr=Cdp()
        )
        CliArgs.frame_types["l2_cfm"] = CliArg(
            cli_arg="--l2-cfm", desc="CFM CCM", hdr=Cfm()
        )
        CliArgs.frame_types["l2_isis_l1_hello"] = CliArg(
            cli_arg="--l2-isis-l1-hello",
            desc="IS-IS P2P Level 1 Hello",
            hdr=IsIsL1Hello(),
        )
        CliArgs.frame_types["l2_isis_l2_hello"] = CliArg(
            cli_arg="--l2-isis-l2-hello",
            desc="IS-IS P2P Level 2 Hello",
            hdr=IsIsL2Hello(),
        )
        CliArgs.frame_types["l2_lacp"] = CliArg(
            cli_arg="--l2-lacp", desc="LACP message", hdr=Lacp()
        )
        CliArgs.frame_types["l2_lldp"] = CliArg(
            cli_arg="--l2-lldp", desc="LLDP message", hdr=Lldp()
        )
        CliArgs.frame_types["l2_macsec"] = CliArg(
            cli_arg="--l2-macsec", desc="MacSec message", hdr=MacSec()
        )
        CliArgs.frame_types["l2_mstp"] = CliArg(
            cli_arg="--l2-mstp", desc="Multiple STP message", hdr=Mstp()
        )
        CliArgs.frame_types["l2_rarp"] = CliArg(
            cli_arg="--l2-rarp", desc="ARP response", hdr=Rarp()
        )
        CliArgs.frame_types["l2_rstp"] = CliArg(
            cli_arg="--l2-rstp",
            desc="Rapid STP message",
            hdr=Rstp(),
        )
        CliArgs.frame_types["l2_rpvstp"] = CliArg(
            cli_arg="--l2-rpvstp",
            desc="Rapid Per-VLAN STP (PVST+) message",
            hdr=Rpvstp(),
        )
        CliArgs.frame_types["l2_stp"] = CliArg(
            cli_arg="--l2-stp", desc="STP message", hdr=Stp()
        )
        CliArgs.frame_types["l3_bfdasync"] = CliArg(
            cli_arg="--l3-bfdasync",
            desc="BFD message (async Mode)",
            hdr=BfdAsync(),
        )
        CliArgs.frame_types["l3_bfdcontrol"] = CliArg(
            cli_arg="--l3-bfdcontrol",
            desc="BFD Control message",
            hdr=BfdControl(),
        )
        CliArgs.frame_types["l3_bfdecho"] = CliArg(
            cli_arg="--l3-bfdecho",
            desc="BFD message (echo Mode)",
            hdr=BfdEcho(),
        )
        CliArgs.frame_types["l3_bfdmicro"] = CliArg(
            cli_arg="--l3-bfdmicro",
            desc="BFD Control message (Micro-BFD/BoB)",
            hdr=BfdMicro(),
        )
        CliArgs.frame_types["l3_bgp"] = CliArg(
            cli_arg="--l3-bgp",
            desc="BGP Keepalive message",
            hdr=Bgp(),
        )
        CliArgs.frame_types["l3_eigrp2v4hello"] = CliArg(
            cli_arg="--l3-eigrp2v4hello",
            desc="EIGRPv2 IPv4 Hello message",
            hdr=EigrpV4Hello(),
        )
        CliArgs.frame_types["l3_eigrp2v6hello"] = CliArg(
            cli_arg="--l3-eigrp2v6hello",
            desc="EIGRPv2 IPv6 Hello message",
            hdr=EigrpV6Hello(),
        )
        CliArgs.frame_types["l3_icmpv4echorequest"] = CliArg(
            cli_arg="--l3-icmpv4echorequest",
            desc="ICMPv4 Echo Request message",
            hdr=IcmpV4EchoRequest(),
        )
        CliArgs.frame_types["l3_icmpv4echoreply"] = CliArg(
            cli_arg="--l3-icmpv4echoreply",
            desc="ICMPv4 Echo Reply message",
            hdr=IcmpV4EchoReply(),
        )
        CliArgs.frame_types["l3_icmpv6echorequest"] = CliArg(
            cli_arg="--l3-icmpv6echorequest",
            desc="ICMPv6 Echo Request message",
            hdr=IcmpV6EchoRequest(),
        )
        CliArgs.frame_types["l3_icmpv6echoreply"] = CliArg(
            cli_arg="--l3-icmpv6echoreply",
            desc="ICMPv6 Echo Reply message",
            hdr=IcmpV6EchoReply(),
        )
        CliArgs.frame_types["l3_igmpv3query"] = CliArg(
            cli_arg="--l3-igmpv3query",
            desc="IGMPv3 Query message",
            hdr=IgmpV3Query(),
        )
        CliArgs.frame_types["l3_igmpv3report"] = CliArg(
            cli_arg="--l3-igmpv3report",
            desc="IGMPv3 Report message",
            hdr=IgmpV3Report(),
        )
        CliArgs.frame_types["l3_mldv2query"] = CliArg(
            cli_arg="--l3-mldv2query",
            desc="MLDv2 Query message",
            hdr=MldV2Query(),
        )
        CliArgs.frame_types["l3_mldv2report"] = CliArg(
            cli_arg="--l3-mldv2report",
            desc="MLDv2 Response message",
            hdr=MldV2Report(),
        )
        CliArgs.frame_types["l3_multicastv4"] = CliArg(
            cli_arg="--l3-multicastv4",
            desc="IPv4 Multicast message",
            hdr=MulticastV4(),
        )
        CliArgs.frame_types["l3_multicastv6"] = CliArg(
            cli_arg="--l3-multicastv6",
            desc="IPv4 Multicast message",
            hdr=MulticastV6(),
        )
        CliArgs.frame_types["l3_ospfv2hello"] = CliArg(
            cli_arg="--l3-ospfv2hello",
            desc="OSPFv2 Hello message",
            hdr=OspfV2Hello(),
        )
        CliArgs.frame_types["l3_ospfv2lsa"] = CliArg(
            cli_arg="--l3-ospfv2lsa",
            desc="OSPFv2 LSA message",
            hdr=OspfV2Lsa(),
        )
        CliArgs.frame_types["l3_ospfv3hello"] = CliArg(
            cli_arg="--l3-ospfv3hello",
            desc="OSPFv3 Hello message",
            hdr=OspfV3Hello(),
        )
        CliArgs.frame_types["l3_ospfv3lsa"] = CliArg(
            cli_arg="--l3-ospfv3lsa",
            desc="OSPFv3 LSA message",
            hdr=OspfV3Lsa(),
        )
        CliArgs.frame_types["l3_vrrpv2"] = CliArg(
            cli_arg="--l3-vrrpv2",
            desc="VRRPv2 IPV4 message",
            hdr=VrrpV2(),
        )
        CliArgs.frame_types["l3_vrrpv3"] = CliArg(
            cli_arg="--l3-vrrpv3",
            desc="VRRPv3 IPv6 message",
            hdr=VrrpV3(),
        )

    @staticmethod
    def create_parser() -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            description="Create RAndom Packets - Send and receive packets using Scapy",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        )
        parser.add_argument(
            "-c",
            "--count",
            help="Number of packets to send",
            type=int,
            required=False,
            default=Settings.PACKET_COUNT,
        )
        parser.add_argument(
            "-i",
            "--interface",
            help="Interface",
            type=str,
            required=False,
            default=Settings.INTERFACE,
        )
        parser.add_argument(
            "-n",
            "--no-pad",
            help="Disable automatic padding of frames to be at least 64 bytes long",
            default=False,
            action="store_true",
            required=False,
        )
        parser.add_argument(
            "-p",
            "--pcap",
            help="PCAP file to write received frames to in Rx mode, "
            "or write transmitted frames to in Tx mode",
            type=str,
            required=False,
            default=None,
        )
        parser.add_argument(
            "-r",
            "--rx",
            help="Receive instead of transmit (default is tx)",
            default=Settings.RX,
            action="store_true",
            required=False,
        )
        parser.add_argument(
            "-u",
            "--unicast",
            help="Send a unicast packet to populate the MAC tables in the "
            "network, with the unicast MAC address used for testing, "
            "before sending the chosen test frame type",
            default=False,
            action="store_true",
            required=False,
        )

        vlan_group = parser.add_argument_group(
            "QoS Settings", "Set a CoS/DSCP values"
        )
        vlan_group.add_argument(
            "--l2-qos",
            help="Specify an 802.1P value. If -v is not used, "
            "and this is non-zero, traffic will be tagged with VLAN 0.",
            type=int,
            required=False,
            default=None,
        )
        vlan_group.add_argument(
            "--l3-qos",
            help="Specify a DSCP value.",
            type=int,
            required=False,
            default=None,
        )

        vlan_group = parser.add_argument_group(
            "VLAN Tag(s)", "Add a VLAN tag(s)"
        )
        vlan_group.add_argument(
            "-q",
            "--qinq",
            help="Specify an inner VLAN tag (requires -v). "
            "Note: QinQ doesn't work with MacSec!",
            type=int,
            required=False,
            default=None,
        )
        vlan_group.add_argument(
            "-v",
            "--vlan",
            help="Specify an outer VLAN tag",
            type=int,
            required=False,
            default=None,
        )

        traffic_group = parser.add_argument_group(
            "Traffic Type", "Type of traffic to tx/rx [REQUIRED]"
        )
        exclusive_args = traffic_group.add_mutually_exclusive_group(
            required=True
        )
        CliArgs.generate_frame_args()
        for frame_type in CliArgs.frame_types.values():
            exclusive_args.add_argument(
                frame_type.cli_arg,
                help=frame_type.desc,
                default=False,
                action="store_true",
                required=False,
            )
        return parser

    @staticmethod
    def parse_cli_args() -> dict[str, Any]:
        parser = CliArgs.create_parser()
        args = vars(parser.parse_args())

        if Settings.INTERFACE != args["interface"]:
            Settings.INTERFACE = args["interface"]

        if Settings.PACKET_COUNT != args["count"]:
            Settings.PACKET_COUNT = args["count"]

        if args["no_pad"]:
            Settings.PADDING = False

        if args["pcap"]:
            Settings.PCAP = args["pcap"]

        if args["qinq"]:
            if not args["vlan"]:
                raise ValueError(f"Can't use -q without -v")
            Settings.QINQ = args["qinq"]

        if args["rx"]:
            Settings.RX = args["rx"]

        if args["unicast"]:
            Settings.UNICAST = args["unicast"]

        if args["vlan"]:
            Settings.VLAN = args["vlan"]

        if args["l2_qos"] != None:
            if args["l2_qos"] > 7 or args["l2_qos"] < 0:
                raise ValueError(
                    f"CoS must be from 0-7 inclusive, not {args['l2_qos']}"
                )
            if Settings.VLAN == None:
                Settings.VLAN = 0
            Settings.COS = args["l2_qos"]

        if args["l3_qos"] != None:
            if args["l3_qos"] > 56 or args["l3_qos"] < 0:
                raise ValueError(
                    f"DSCP must be from 0-56 inclusive, not {args['l3_qos']}"
                )
            Settings.DSCP = args["l3_qos"] << 2

        Settings.FRAME = CliArgs.get_frame_from_args(args)

        """
        The frame is built whilst parsing the CLI args but some of the args may have
        affected how the frame should be built. So, rebuild it.
        """
        Settings.FRAME.rebuild()

        return args
