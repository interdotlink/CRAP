from __future__ import annotations

from scapy.contrib.ospf import OSPFv3_Hdr, OSPFv3_Hello  # type: ignore
from scapy.data import ETH_P_IPV6  # type: ignore
from scapy.layers.inet6 import IPv6  # type: ignore

from crap.protocols.l2 import build_l2
from crap.settings import Settings

from .base_header import BaseHeader


class OspfV3Hello(BaseHeader):
    def __init__(self: OspfV3Hello) -> None:
        """
        Instance ID:
        https://www.rfc-editor.org/rfc/rfc5838#section-2.1
        ...
        Instance ID # 64   -  # 95     IPv4 unicast AF

        HELLO Options:
        https://www.rfc-editor.org/rfc/rfc5340#section-4.2.1.1
        The
        E-bit is set if and only if the interface attaches to a regular
        area, i.e., not a stub or NSSA area.  Similarly, the N-bit is set
        if and only if the interface attaches to an NSSA area (see
        [NSSA]).  Finally, the DC-bit is set if and only if the router
        wishes to suppress the sending of future Hellos over the interface
        (see [DEMAND]).
        ...
        https://www.rfc-editor.org/rfc/rfc5340#appendix-A.2
        R-bit
        This bit (the `Router' bit) indicates whether the originator is an
        active router.  If the router bit is clear, then routes that
        transit the advertising node cannot be computed.
        ...
        AF-Bit: # https://www.rfc-editor.org/rfc/rfc5838#section-2.2
        """
        self.data = (
            IPv6(
                src=Settings.IPV6_HOST1_LL,
                dst=Settings.IPV6_MC_OSPF,
                hlim=1,
                tc=Settings.DSCP,
            )
            / OSPFv3_Hdr(
                src=Settings.IPV4_HOST1_LOOPBACK,
                type=Settings.OSPF_MESSAGE_HELLO,
                instance=64,
            )
            / OSPFv3_Hello(
                intid=6,
                router=Settings.IPV4_HOST1_LOOPBACK,
                backup=Settings.IPV4_HOST2_LOOPBACK,
                options=(
                    Settings.OSPF_OPTION_EXTERNAL
                    | Settings.OSPF_OPTION_ROUTER
                    | Settings.OSPF_OPTION_AF
                ),
            )
        )

        # Off-set to OSPF Message Type (zero indexed)
        self.set_filter(
            f" and proto ospf"
            f" and src {Settings.IPV6_HOST1_LL}"
            f" and dst {Settings.IPV6_MC_OSPF}"
            f" and ip6[{len(IPv6())+1}] == {Settings.OSPF_MESSAGE_HELLO}"
        )

        build_l2(
            dst=Settings.MAC_MC_IPV6_OSPF,
            eth2=True,
            etype=ETH_P_IPV6,
            header=self,
            src=Settings.MAC_HOST1,
        )

        self.build()
