# Evaluation

Produced by `python tools/evaluate.py --real DIR --out docs/report.json` (machine: Linux x86_64, Python 3.13.16,
seed 1000; the run took 145.2 s).

**What this is and is not.** There is no way to get a real network that attacks on command, so the accuracy numbers come
from captures whose content is known: `pcaplab.synth` builds the ordinary traffic of a small network (web, DNS, NTP,
ping, ARP) plus a few things that look odd but are harmless (a client that opens ten ports of a server, a monitor that
checks twelve service ports every five minutes, a CDN with many short names, a few typos, a client that polls at random
intervals), and injects scans, a DNS tunnel, a flood of names that do not exist, beacons, ARP spoofing, clear-text
logins and a lossy upload at recorded places. What was injected is written down by the generator, independently of the
detectors. This shows that the detectors do what they claim and where they stop. It does not show how often a real
network looks like the generator: see [limitations](limitations.md). Two things are measured on code and data that
the author did not write: the decoder against scapy (section 1) and against real captures (section 5).

The detectors' thresholds were set while looking at seeds 1 to 5. The numbers below use seeds from 1000 on, which
were not looked at before the numbers were produced.

## 1. Is the decoder right?

scapy 2.6.1 builds 20,000 random packets (arp 1492, dns_q 1561, dns_r 1571, http 1553, icmp4 1488, icmp6 1499, sll 1574, sll2 1534, tcp4 1627, tcp6 1525, udp4 1506, udp6 1470, vlan 1600) with chosen field values; pcaplab reads the bytes and
every field is compared with what was put in (157,549 fields: addresses, ports, flags, sequence numbers,
TTL, VLAN, ICMP type, DNS name, type, answers and response code, HTTP method, path and host, payload, link-layer
addresses).

**0 fields differ.**

## 2. Findings against what was injected

40 captures of 1800 s each (1,714,358 packets) with the injected things, and 15 captures of
the same length without any attack (605,704 packets, harmless oddities only).

| injected | count | found |
|---|---|---|
| port scan | 120 | 120 |
| DNS tunnel | 40 | 40 |
| NXDOMAIN storm | 40 | 40 |
| beacon | 80 | 80 |
| ARP conflict | 40 | 40 |
| clear-text password | 80 | 80 |
| TCP retransmissions | 40 | 40 |
| **all** | **440** | **440** |

- **False findings: 0** in the captures with attacks, **0** in the quiet ones. Two findings for one thing: 0.
- The slow scan (one probe every 20 s, injected 40 times) was found 0 times, as the documented limit says.

Three rules a first script would use, on the same captures (alerts include the true ones):

| naive rule | alerts | of them false | alerts in the quiet captures |
|---|---|---|---|
| port scan: 15 different host:port targets in the whole capture | 635 | 515 | 180 |
| beacon: 8 connections to one destination, however irregular | 600 | 520 | 195 |
| NXDOMAIN storm: 5 names that do not exist | 80 | 40 | 15 |
| DNS tunnel: 25 different names below one domain | 80 | 40 | 15 |

pcaplab's rules need what the naive ones leave out: the target never answering or the conversation carrying no data
(scans), regular gaps (beacons), a share of the client's answers (NXDOMAIN), and length and randomness of the names
(tunnels).

## 3. Where each detector stops

8 runs per cell, a single injected event in an otherwise empty capture. Moving a threshold has a cost on both sides: the
last four tables run the full captures of section 2 (with their harmless oddities) at other thresholds.

**Scan speed** (200 ports; the rule needs 15 targets in 60 s, that is 0.25 probes per second)

| probes per second | 0.1 | 0.2 | 0.3 | 0.5 | 1 | 5 | 50 |
|---|---|---|---|---|---|---|---|
| found | 0/8 | 0/8 | 8/8 | 8/8 | 8/8 | 8/8 | 8/8 |

**Scan size** (at 20 probes per second)

| ports | 5 | 10 | 14 | 15 | 16 | 30 | 100 |
|---|---|---|---|---|---|---|---|
| found | 0/8 | 0/8 | 0/8 | 8/8 | 8/8 | 8/8 | 8/8 |

**Beacon regularity** (30 connections, one a minute, random jitter of ± the given share)

| jitter | 0.0 | 0.05 | 0.1 | 0.2 | 0.3 | 0.5 | 0.8 |
|---|---|---|---|---|---|---|---|
| found | 8/8 | 8/8 | 8/8 | 8/8 | 6/8 | 0/8 | 0/8 |

**Beacon length** (jitter 5%)

| connections | 5 | 7 | 8 | 12 | 30 |
|---|---|---|---|---|---|
| found | 0/8 | 0/8 | 8/8 | 8/8 | 8/8 |

**DNS tunnel size**

| names | 10 | 20 | 24 | 25 | 40 | 100 |
|---|---|---|---|---|---|---|
| found | 0/8 | 0/8 | 0/8 | 8/8 | 8/8 | 8/8 |

**Effect of the thresholds** on the full captures:

| scan targets (default 15) | 5 | 10 | 15 | 25 | 40 |
|---|---|---|---|---|---|
| injected things found | 110 | 110 | 110 | 110 | 106 |
| false findings | 60 | 60 | 0 | 0 | 0 |

| beacon spread (default 0.15) | 0.02 | 0.05 | 0.15 | 0.4 | 0.8 |
|---|---|---|---|---|---|
| injected things found | 93 | 110 | 110 | 110 | 110 |
| false findings | 0 | 0 | 0 | 0 | 0 |

| beacon connections (default 8) | 3 | 5 | 8 | 12 | 20 |
|---|---|---|---|---|---|
| injected things found | 110 | 110 | 110 | 110 | 109 |
| false findings | 155 | 113 | 0 | 0 | 0 |

| NXDOMAIN names (default 20) | 3 | 5 | 10 | 20 | 40 |
|---|---|---|---|---|---|
| injected things found | 110 | 110 | 110 | 110 | 108 |
| false findings | 10 | 10 | 0 | 0 | 0 |

## 4. Cost

One capture of the generator repeated to a larger file (the file sits on disk; each stage is a separate process, best of
three; peak memory is the high-water mark of the process).

| format | packets | file | read (packets/s) | + decode | + analyze | + detect | peak memory |
|---|---|---|---|---|---|---|---|
| pcap | 499,728 | 266.2 MiB | 1,036,010 | 218,780 | 125,125 | 125,917 | 52.9 MiB |
| pcapng | 499,728 | 274.3 MiB | 525,846 | 173,725 | 104,405 | 100,795 | 53 MiB |

Reading and decoding keep about 14.9 MiB whatever the size of the file. Analysis keeps one record per flow, about
1.4 KiB each (28,389 flows here, 52.5 MiB in all): memory grows with the number of
conversations, not with the number of packets.

## 5. Captures taken by other people

11 captures from the Wireshark test suite (`test/captures` in the wireshark/wireshark repository: DHCP in pcap, nanosecond
pcap and pcapng, DNS, mDNS and IPv6, HTTP, TLS 1.2 and 1.3, an ARP file in a link type pcaplab does not read). They are
not stored in this repository; `tools/evaluate.py --real DIR` reads whatever is in `DIR`. scapy reads the same files
and the fields it and pcaplab both have are compared (addresses, ports, TCP flags and sequence numbers, ICMP type, DNS
name).

pcaplab read 694 packets, scapy 694; **2,796 fields equal, 0 different**;
1 packet could not be decoded (the Frame Relay file `arp.pcap`, link type 107).

| file | packets | flows | fields equal | different | TLS server names |
|---|---|---|---|---|---|
| `arp.pcap` | 1 | 0 | 0 | 0 | - |
| `dhcp-nanosecond.pcap` | 4 | 2 | 20 | 0 | - |
| `dhcp.pcap` | 4 | 2 | 20 | 0 | - |
| `dhcp.pcapng` | 4 | 2 | 20 | 0 | - |
| `dns-mdns.pcap` | 587 | 163 | 2091 | 0 | *.immedia-semi.com |
| `dns_port.pcap` | 4 | 2 | 20 | 0 | - |
| `http.pcap` | 1 | 1 | 7 | 0 | - |
| `ipv6.pcap` | 1 | 1 | 2 | 0 | - |
| `rsasnakeoil2.pcap` | 58 | 2 | 406 | 0 | - |
| `tls12-dsb.pcapng` | 17 | 2 | 119 | 0 | example.com, example.net |
| `tls13-rfc8446.pcap` | 13 | 2 | 91 | 0 | - |

No detector reported anything on these files, as expected for captures without attacks. They say nothing about
detection rates.
