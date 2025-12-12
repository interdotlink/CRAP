# Create RAndom Packets

## Overview

CRAP is a Python script which has a very basic work flow to test the transmission, and optionally, the reception of frames and packets.

CRAP runs in two modes, tx/transmit mode and rx/receive mode. If you only want to send traffic then you can simply run CRAP, which runs in tx mode by default, and choose the type of traffic you want to send. If you wish to verify the traffic is also received, you need to run a second copy of CRAP in rx mode. You also have to specify the same type of traffic in rx mode because CRAP only listens for incoming traffic of the specified type.

If you want to run tcpdump and manually capture traffic sent by CRAP yourself, rather than using rx mode, CRAP always prints a libpcap filter which can be used with tcpdump to capture the traffic, when it runs in tx mode.

A typical use case for CRAP is testing the transparency of a L2 VPN:

```text
  ┌─────────┐ L2 VPN ┌─────────┐
  │ Router1 ┼────────► Router2 │
  └────▲────┘        └────┬────┘
┌──────┼──────────────────┼──────┐
│ ┌────┴────┐        ┌────▼────┐ │
│ │ CRAP Tx │        │ CRAP Rx │ │Linux Server
│ └─────────┘        └─────────┘ │
└────────────────────────────────┘
```

## Features

The following output shows the traffic types CRAP can generated. See the [Protocol Definitions](#protocol-definitions) section to learn exactly what kind of frame/packet CRAP sends.

```shell
$ python3 ./crap.py -h
usage: crap.py [-h] [-c COUNT] [-i INTERFACE] [-n] [-p PCAP] [-r] [-u] [--l2-qos L2_QOS] [--l3-qos L3_QOS] [-q QINQ] [-v VLAN]
               (--l2-arp | --l2-cdp | --l2-cfm | --l2-isis-l1-hello | --l2-isis-l2-hello | --l2-lacp | --l2-lldp | --l2-macsec | --l2-mstp | --l2-rarp | --l2-rstp | --l2-rpvstp | --l2-stp | --l3-bfdasync | --l3-bfdcontrol | --l3-bfdecho | --l3-bfdmicro | --l3-bgp | --l3-eigrp2v4hello | --l3-eigrp2v6hello | --l3-icmpv4echorequest | --l3-icmpv4echoreply | --l3-icmpv6echorequest | --l3-icmpv6echoreply | --l3-igmpv3query | --l3-igmpv3report | --l3-mldv2query | --l3-mldv2report | --l3-multicastv4 | --l3-multicastv6 | --l3-ospfv2hello | --l3-ospfv2lsa | --l3-ospfv3hello | --l3-ospfv3lsa | --l3-vrrpv2 | --l3-vrrpv3)

Create RAndom Packets - Send and receive packets using Scapy

options:
  -h, --help            show this help message and exit
  -c COUNT, --count COUNT
                        Number of packets to send (default: 5)
  -i INTERFACE, --interface INTERFACE
                        Interface (default: veth0)
  -n, --no-pad          Disable automatic padding of frames to be at least 64 bytes long (default: False)
  -p PCAP, --pcap PCAP  PCAP file to write received frames to in Rx mode, or write transmitted frames to in Tx mode (default: None)
  -r, --rx              Receive instead of transmit (default is tx) (default: False)
  -u, --unicast         Send a unicast packet to populate the MAC tables in the network, with the unicast MAC address used for testing, before sending the chosen test frame type (default: False)

QoS Settings:
  Set a CoS/DSCP values

  --l2-qos L2_QOS       Specify an 802.1P value. If -v is not used, and this is non-zero, traffic will be tagged with VLAN 0. (default: None)
  --l3-qos L3_QOS       Specify a DSCP value. (default: None)

VLAN Tag(s):
  Add a VLAN tag(s)

  -q QINQ, --qinq QINQ  Specify an inner VLAN tag (requires -v). Note: QinQ doesn't work with MacSec! (default: None)
  -v VLAN, --vlan VLAN  Specify an outer VLAN tag (default: None)

Traffic Type:
  Type of traffic to tx/rx [REQUIRED]

  --l2-arp              ARP request (default: False)
  --l2-cdp              CDP message (default: False)
  --l2-cfm              CFM CCM (default: False)
  --l2-isis-l1-hello    IS-IS P2P Level 1 Hello (default: False)
  --l2-isis-l2-hello    IS-IS P2P Level 2 Hello (default: False)
  --l2-lacp             LACP message (default: False)
  --l2-lldp             LLDP message (default: False)
  --l2-macsec           MacSec message (default: False)
  --l2-mstp             Multiple STP message (default: False)
  --l2-rarp             ARP response (default: False)
  --l2-rstp             Rapid STP message (default: False)
  --l2-rpvstp           Rapid Per-VLAN STP (PVST+) message (default: False)
  --l2-stp              STP message (default: False)
  --l3-bfdasync         BFD message (async Mode) (default: False)
  --l3-bfdcontrol       BFD Control message (default: False)
  --l3-bfdecho          BFD message (echo Mode) (default: False)
  --l3-bfdmicro         BFD Control message (Micro-BFD/BoB) (default: False)
  --l3-bgp              BGP Keepalive message (default: False)
  --l3-eigrp2v4hello    EIGRPv2 IPv4 Hello message (default: False)
  --l3-eigrp2v6hello    EIGRPv2 IPv6 Hello message (default: False)
  --l3-icmpv4echorequest
                        ICMPv4 Echo Request message (default: False)
  --l3-icmpv4echoreply  ICMPv4 Echo Reply message (default: False)
  --l3-icmpv6echorequest
                        ICMPv6 Echo Request message (default: False)
  --l3-icmpv6echoreply  ICMPv6 Echo Reply message (default: False)
  --l3-igmpv3query      IGMPv3 Query message (default: False)
  --l3-igmpv3report     IGMPv3 Report message (default: False)
  --l3-mldv2query       MLDv2 Query message (default: False)
  --l3-mldv2report      MLDv2 Response message (default: False)
  --l3-multicastv4      IPv4 Multicast message (default: False)
  --l3-multicastv6      IPv4 Multicast message (default: False)
  --l3-ospfv2hello      OSPFv2 Hello message (default: False)
  --l3-ospfv2lsa        OSPFv2 LSA message (default: False)
  --l3-ospfv3hello      OSPFv3 Hello message (default: False)
  --l3-ospfv3lsa        OSPFv3 LSA message (default: False)
  --l3-vrrpv2           VRRPv2 IPV4 message (default: False)
  --l3-vrrpv3           VRRPv3 IPv6 message (default: False)
```

## Install

* (optional) Set up a Python virtual environment

```shell
sudo apt install --no-install-recommends python3-venv python3-pip
python3 -m venv --without-pip .venv && source .venv/bin/activate
```

* Install the required Python modules:

```shell
python3 -m ensurepip
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
```

* You should be able to run the script now:

```shell
./crap.py -h
```

You need to run crap.py as root in order to send and receive raw frames. When using sudo a different Python interpreter is used than the one in the venv you just set up, which will be missing the dependencies, therefore you see `sudo -E $(which python3) ./crap.py` throughout this README. This is not needed if you are NOT using a venv or running in Docker.

## Known Issues

* QinQ in not currently supported for MacSec, only untagged or a single VLAN tag are supported by MacSec.

## Quick Start Reference

Set up a veth pair and send traffic between them:

```shell
# Terminal 1
NS=scapy
sudo ip netns add $NS && \
sudo ip link add veth0 type veth peer name veth1  && \
sudo ip link set veth1 netns $NS && \
sudo ip netns exec $NS ip link set up dev veth1 && \
sudo ip link set up dev veth0

# Terminal 2
NS=scapy
sudo -E ip netns exec $NS $(which python3) ./crap.py -r -i veth1 --l3-mldv2query
sudo ip netns exec $NS wireshark -ki veth1

# Terminal 1
sudo -E $(which python3) ./crap.py --l3-mldv2query

# Clean-up
sudo ip netns delete $NS
sudo ip link del veth0 type veth peer name veth1
```

## Detailed Example

### Sending Traffic

Set up a pair of virtual interfaces which are linked together, and send some traffic into one of them:

* Set up a pair of virtual interfaces:

```shell
NS=crap
sudo ip netns add $NS && \
sudo ip link add veth0 type veth peer name veth1  && \
sudo ip link set veth1 netns $NS && \
sudo ip netns exec $NS ip link set up dev veth1 && \
sudo ip link set up dev veth0
```

* The minimum you need to specify, is the type of packet you want to send and the interface to send it on. In this example ARP requests are being sent:

```shell
sudo $(which python3) ./crap.py --l2-arp -i veth0

Using frame: <l2.Arp object at 0x7ff4a29846d0>
Packet data: <Ether  dst=00:03:00:00:00:01 src=00:03:00:00:00:02 type=RARP |> <ARP  op=is-at hwsrc=00:03:00:00:00:02 psrc=10.200.200.2 hwdst=00:03:00:00:00:01 pdst=10.200.200.1 |>
Filter data: ether src 00:03:00:00:00:01 and ether dst FF:FF:FF:FF:FF:FF and ether proto 0x0806

.....
Sent 5 packets.

# If using a virtual environment, you will need to specify the python interpreter for this environment, when using sudo:
sudo -E $(which python3) ./crap.py --l2-arp -i veth0
```

* If you want to see the packets which were sent, start Wireshark on the other virtual interface:

```shell
NS=crap
sudo ip netns exec $NS wireshark -ki veth1
```

### Receiving Traffic

In order to verify the traffic which was sent by CRAP into the first virtual interface, run CRAP on the second virtual interface in rx mode, and specify the kind of packet is needs to listen for. CRAP will generate a libpcap filter which only accepts the the specified type of packet.

* Start listening on the second virtual interface for ARP packets:

```shell
NS=crap
sudo -E ip netns exec $NS $(which python3) ./crap.py --l2-arp -r -i veth1

Using frame: <l2.Arp object at 0x7ff7414c2e90>
Packet data: <Ether  dst=00:03:00:00:00:01 src=00:03:00:00:00:02 type=RARP |> <ARP  op=is-at hwsrc=00:03:00:00:00:02 psrc=10.200.200.2 hwdst=00:03:00:00:00:01 pdst=10.200.200.1 |>
Filter data: ether src 00:03:00:00:00:01 and ether dst FF:FF:FF:FF:FF:FF and ether proto 0x0806

Starting capture using filter: ether src 00:03:00:00:00:01 and ether dst FF:FF:FF:FF:FF:FF and ether proto 0x0806
```

* From the first interface, send the ARP packets:

```shell
sudo -E $(which python3) ./crap.py -i veth0 --l2-arp

Using frame: <l2.Arp object at 0x7ff4a29846d0>
Packet data: <Ether  dst=00:03:00:00:00:01 src=00:03:00:00:00:02 type=RARP |> <ARP  op=is-at hwsrc=00:03:00:00:00:02 psrc=10.200.200.2 hwdst=00:03:00:00:00:01 pdst=10.200.200.1 |>
Filter data: ether src 00:03:00:00:00:01 and ether dst FF:FF:FF:FF:FF:FF and ether proto 0x0806

.....
Sent 5 packets.
```

* On the second interface we see that the same number and type of frames which were transmitted, were received:

```shell
Captured 5 frames
```

* Finally we can delete the virtual interfaces:

```shell
sudo ip netns delete $NS
sudo ip link del veth0 type veth peer name veth1
```

## Protocol Definitions

The following table provides a definition of the of different protocols.

| Control Protocol   | Format                 | Src Mac         | Dst MAC               | Ethertype | LLC/SNAP | Description |
| ------------------ | ---------------------- | --------------- |  -------------------- | --------- | -------- | ----------- |
| ARP                | Ethernet II            | Unicast Source  | 00:00:00:00:00:00     | 0x0806    | None     | IPv4 ARP broadcast |
| BFD Control        | Ethernet II            | Unicast Source  | Unicast Destination   | 0x0800    | None     | BFD Control packet over IPv4 with unicast source and destination IPs |
| BFD Control (Micro-BFD) | Ethernet II       | Unicast Source  | 01:00:5E:90:00:01     | 0x0800    | None     | BFD Control packet for Micro-BFD (BoB) over IPv4 with unicast source and destination IPs, to multicast destination MAC. |
| BFD Echo           | Ethernet II            | Unicast Source  | Unicast Destination   | 0x0800    | None     | BFD Echo packet over IPv4 with own unicast address as source and destination IPs |
| BFD Echo (Async)   | Ethernet II            | Unicast Source  | Unicast Destination   | 0x0800    | None     | BFD Echo packet over IPv4 with distinct unicast source and destination IPs |
| BGP                | Ethernet II            | Unicast Source  | Unicast Destination   | 0x0800/0x86DD | None | IPv4/6 packet with unicast source IP and unicast destination IP, with TCP source port or destination port set to 179 |
| CDP                | IEEE 802.3 + LLC + SNAP| Unicast Source  | 01:00:0C:CC:CC:CC     | None      | DSAP 0xAA, SSAP 0xAA, OUI: 0x00000C, protocol ID: 0x2000 | Cisco Discovery Protocol |
| CFM                | Ethernet II            | Unicast Source  | 01:80:C2:00:00:30-3F  | 0x8902    | None     | IEEE 802.1ag and Y.1731 Connectivity Fault Management. |
| EIGRP v2           | Ethernet II            | Unicast Source  | 01:00:5E:00:00:0A / 33:33:00:00:00:0A | 0x0800/0x86DD | None | IPv4/6 packets with unicast source IP, muticast destination IP (224.0.0.10/FF02::A), and IP protocol 88 |
| E-LMI              | Ethernet II            |                 | 01:80:C2:00:00:07     | 0x88EE    | None     | MEF-16 E-LMI Ethernet Local Management Interface |
| LACP               | Ethernet II            | Unicast Source  | 01:80:C2:00:00:02     | 0x8809    | None     | IEEE 802.3ad / IEEE 802.1AX-2008 Link Aggregation Control Protocol. |
| LLDP               | Ethernet II            | Unicast Source  | 01:80:C2:00:00:0E     | 0x88CC    | None     | IEEE 802.1AB Link Layer Discovery Protocol |
| IGMPv3 Query       | Ethernet II            | Unicast Source  | Multicast Destination | 0x0800    | None     | IGMP packet with IPv4 multicast destination address (224.0.0.0/4) and matching multicast destination MAC. |
| IGMPv3 Response     | Ethernet II            | Unicast Source  | Multicast Destination | 0x0800    | None     | IGMP packet with IPv4 multicast destination address (224.0.0.0/4) and matching multicast destination MAC. |
| IS-IS L1 Hello     | IEEE 802.3 + LLC       | Unicast Source  | 01:80:C2:00:00:14     | None      | DSAP 0xFE, SSAP 0xFE | ISO/IEC 10589 |
| IS-IS L2 Hello     | IEEE 802.3 + LLC       | Unicast Source  | 01:80:C2:00:00:15     | None      | DSAP 0xFE, SSAP 0xFE | ISO/IEC 10589 |
| ES-IS IS->ES       | IEEE 802.8 + LLC       | Unicast Source  | 09:00:2B:00:00:04     | None      |          | ISO/IEC 10589 |
| ES-IS ES->IS       | IEEE 802.8 + LLC       | Unicast Source  | 09:00:2B:00:00:05     | None      |          | ISO/IEC 10589 |
| IPv4 Multicast     | Ethernet II            | Unicast Source  | Multicast Destination | 0x0800    | None     | IPv4 packets with a multicast destination IP (224.0.0.0/4) and matching multicast destination MAC. |
| IPv6 Multicast     | Ethernet II            | Unicast Source  | Multicast Destination | 0x86DD    | None     | IPv6 packets with a multicast destination IP (FF00::/8) and matching multicast destination MAC. |
| MACSec             | Ethernet II            | Unicast Source  | Unicast Destination   | 0x88E5    | None     | IEEE 802.1AE |
| MLDv2 Query        | Ethernet II            | Unicast Source  | Multicast Destination | 0x86DD    | None     | ICMPv6 packet with IPv6 multicast destination address (FF02::16) and matching multicast destination MAC. |
| MLDv2 Report       | Ethernet II            | Unicast Source  | Multicast Destination | 0x86DD    | None     | ICMPv6 packet with IPv6 multicast destination address (FF02::16) and matching multicast destination MAC. |
| MSTP               | IEEE 802.3 + LLC       | Unicast Source  | 01:80:C2:00:00:08     | None      | DSAP 0x42, SSAP 0x42 | IEEE 802.1s, IEEE 802.1q-2014 |
| OAM                | Ethernet II            |                 | 01:80:C2:00:00:02     | 0x8809    | None     | IEEE 802.3ah Ethernet OAM uses the same destination MAC and Ethertype as LACP. |
| OSPFv2 Hello       | Ethernet II            | Unicast Source  | Multicast Destination | 0x0800    | None     | IPv4 packets with a multicast destination IP (224.0.0.5) and matching multicast destination MAC. |
| OSPFv2 LSA         | Ethernet II            | Unicast Source  | Multicast Destination | 0x0800    | None     | IPv4 packets with a multicast destination IP (224.0.0.5) and matching multicast destination MAC. |
| OSPFv3 Hello       | Ethernet II            | Unicast Source  | Multicast Destination | 0x86DD    | None     | IPv6 packets with a multicast destination IP (FF02::5) and matching multicast destination MAC. |
| OSPFv3 LSA         | Ethernet II            | Unicast Source  | Multicast Destination | 0x86DD    | None     | IPv6 packets with a multicast destination IP (FF02::5) and matching multicast destination MAC. |
| <s>Pause Frame</s> | Ethernet II            |                 | 01:80:C2:00:00:01     | 0x8808    | None     | IEEE 802.3x Ethernet Flow Control. **These must not be transported across the service as per the standard.** |
| PVST+              | IEEE 802.3 + LLC       | Unicast Source  | 01:00:0C:CC:CC:CD     | None      | DSAP 0xAA, SSAP 0xAA, OUI: 0x00000C, protocol ID: 0x010b | Rapid Per-VLAN Spanning Tree |
| RARP               | Ethernet II            | Unicast Source  | Unicast Destination   | 0x8035    | None     | IPv4 ARP reply from unicast source MAC, to unicast destination MAC |
| STP                | IEEE 802.3 + LLC       | Unicast Source  | 01:80:C2:00:00:00     | None      | DSAP 0x42, SSAP 0x42 | IEEE 802.1D, IEEE 802.1q-2014 |
| RSTP               | IEEE 802.3 + LLC       | Unicast Source  | 01:80:C2:00:00:00     | None      | DSAP 0x42, SSAP 0x42 | IEEE 802.1w, IEEE 802.1q-2014 |
| UDLD               | IEEE 802.3 + LLC + SNAP| Unicast Source  | 01:00:0C:CC:CC:CC     | None      | DSAP 0xAA, SSAP 0xAA, OUI: 0x00000C, protocol ID: 0x0111 | Unidirection Link Detection Protocol |
| VLAN               | Ethernet II            | Any             | Any                   | 0x8100    | None     | Single- and double-VLAN tagged frames. |
| VRRP v2            | Ethernet II            | 00:00:5E:00: + VRRP GRP ID | 01:00:5E:00:00:12 | 0x0800 | None | IPv4 packets with a unicast source IP and multicast destination IP (224.0.0.18) |
| VRRP v3            | Ethernet II            | 00:00:5e:00: + VRRP GRP ID | 01:00:5E:00:00:18/12 | 0x0800/0x86DD | None | IPv4/6 packets with a unicast source IP and multicast destination IP (224.0.0.18/FF02::12) |
| VTP                | IEEE 802.3 + LLC + SNAP| Unicast Source  | 01:00:0C:CC:CC:CC     | None      | DSAP 0xAA, SSAP 0xAA, OUI: 0x00000C, protocol ID: 0x2003 | Virtual Trunking Protocol |

References:

* <https://standards.ieee.org/products-programs/regauth/grpmac/public/>  
* <https://en.wikipedia.org/wiki/EtherType#Values>  
* <https://wiki.mef.net/display/CESG/MEF+16+-+E-LMI>  
* <https://www.iana.org/assignments/ethernet-numbers/ethernet-numbers.xhtml#ethernet-numbers-6>  
* <https://standards.ieee.org/wp-content/uploads/import/documents/tutorials/macgrp.pdf>  
* <https://www.mef.net/wp-content/uploads/2018/12/MEF-45-1.pdf> (Table 10)  
* <https://wiki.mef.net/download/attachments/54765198/MEF_16.pdf?api=v2> (Page 4)
