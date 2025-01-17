from __future__ import annotations

from scapy.data import ETH_P_IPV6  # type: ignore
from scapy.layers.inet6 import (  # type: ignore
    ICMPv6MLQuery2,
    IPv6,
    IPv6ExtHdrHopByHop,
    RouterAlert,
)

from crap.protocols.l2 import build_l2
from crap.settings import Settings

from .base_header import BaseHeader


class MldV2Query(BaseHeader):
    def __init__(self: MldV2Query) -> None:
        """
        https://www.rfc-editor.org/rfc/rfc3810#section-5
        All MLDv2 messages
        described in this document MUST be sent with a link-local IPv6 Source
        Address, an IPv6 Hop Limit of 1, and an IPv6 Router Alert option
        [RFC2711] in a Hop-by-Hop Options header.

        There are two MLD message types of concern to the MLDv2 protocol
        described in this document:
        o  Multicast Listener Query ([ICMPv6] Type = decimal 130)
        o  Version 2 Multicast Listener Report ([ICMPv6] Type = decimal 143).

        5.1.14.  Source Addresses for Queries
        All MLDv2 Queries MUST be sent with a valid IPv6 link-local source
        address.

        5.1.15.  Destination Addresses for Queries
        In MLDv2, General Queries are sent to the link-scope all-nodes
        multicast address (FF02::1).
        """
        self.data = (
            IPv6(
                dst=Settings.IPV6_MC_ALL_NODES,
                hlim=1,
                src=Settings.IPV6_HOST1_LL,
                tc=Settings.DSCP,
            )
            / IPv6ExtHdrHopByHop(options=RouterAlert())
            / ICMPv6MLQuery2()
        )

        # The off-set of 48 is for the IPv6 header + extension header
        self.set_filter(
            f" and ip6 and src {Settings.IPV6_HOST1_LL}"
            f" and dst {Settings.IPV6_MC_ALL_NODES}"
            f" and ip6[{len(IPv6()/IPv6ExtHdrHopByHop())}] =="
            f" {Settings.ICMPV6_TYPE_MLD_QUERY}"
        )

        build_l2(
            dst=Settings.MAC_MC_IPV6_ALL_NODES,
            eth2=True,
            etype=ETH_P_IPV6,
            header=self,
            src=Settings.MAC_HOST1,
        )

        self.build()
