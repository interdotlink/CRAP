from __future__ import annotations

from scapy.contrib.macsec import MACsecSA  # type: ignore
from scapy.layers.inet import ICMP, IP  # type: ignore
from scapy.layers.l2 import Dot1Q, Ether  # type: ignore
from scapy.packet import Packet  # type: ignore

from crap.settings import Settings

from .base_header import BaseHeader


class MacSec(BaseHeader):
    def __init__(self: MacSec) -> None:
        macsec_payload = (
            Ether(dst=Settings.MAC_HOST2, src=Settings.MAC_HOST1)
            / IP(
                dst=Settings.IPV4_HOST2,
                src=Settings.IPV4_HOST1,
                tos=Settings.DSCP,
            )
            / ICMP()
        )

        macsec_sa = MACsecSA(
            sci=Settings.MACSEC_SCI,
            an=Settings.MACSEC_AN,
            pn=Settings.MACSEC_PN,
            key=Settings.MACSEC_KEY,
            icvlen=Settings.MACSEC_ICVLEN,
            encrypt=Settings.MACSEC_ENCRYPT,
            send_sci=Settings.MACSEC_SEND_SCI,
            xpn_en=Settings.MACSEC_XPN_EN,
            ssci=Settings.MACSEC_SSCI,
            salt=Settings.MACSEC_SALT,
        )

        """
        MACSec must encrypte an Ethernet frame, even though the MAC addresses
        and EtherType are sent as clear-text, they are required as part of the
        process, therefor we build the whole frame (encap) then encrypt it:
        """
        macsec_encapped_frame: Packet = macsec_sa.encap(macsec_payload)
        macsec_encrypted_frame: Packet = macsec_sa.encrypt(
            macsec_encapped_frame
        )
        self.data = macsec_encrypted_frame
        self.set_filter(
            f"ether src {Settings.MAC_HOST1} and ether dst {Settings.MAC_HOST2}"
            f" and ether proto {hex(Settings.ETHERTYPE_MACSEC)}"
        )

        """
        Because all the Ethernet headers are part of the MACSec process
        (even though the SRC+DST MAC and EType must remain as clear text for a
        switch to forward them), MACSec + Dot1Q is not defined in any standard
        because even the Dot1Q tag *is* encrypted. However, vendors like Cisco
        implement MACSec + Dot1Q anyway.
        If we are sending with a VLAN tag, we have to insert the VLAN tag between
        the Ethernet header and start of the MACSec header:
        """
        if Settings.VLAN != None:
            ether_layer = macsec_encrypted_frame.firstlayer()
            ether_layer.type = Settings.ETHERTYPE_VLAN
            if type(Settings.COS) == int:
                prio = Settings.COS
            else:
                prio = 0
            vlan_layer = Dot1Q(prio=prio, vlan=Settings.VLAN)
            vlan_layer.add_payload(ether_layer.payload)
            ether_layer.remove_payload()
            ether_layer.add_payload(vlan_layer)
            self.data = ether_layer
            self.set_filter(
                f"ether src {Settings.MAC_HOST1} and ether dst {Settings.MAC_HOST2}"
                f" and vlan {Settings.VLAN}"
                f" and ether proto {hex(Settings.ETHERTYPE_MACSEC)}"
            )

        self.build()
