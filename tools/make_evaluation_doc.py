"""Write docs/evaluation.md from docs/report.json (run from the repository root)."""

import json
from pathlib import Path

d = json.loads(Path("docs/report.json").read_text())
E_, X, P, B, C, R = d["environment"], d["crosscheck"], d["pipeline"], d["boundaries"], d["cost"], d["real"]
Q, BL = P["quiet"], P["baseline"]
KINDS = {
    "port-scan": "port scan",
    "dns-tunnel": "DNS tunnel",
    "nxdomain-storm": "NXDOMAIN storm",
    "beacon": "beacon",
    "arp-conflict": "ARP conflict",
    "cleartext-credentials": "clear-text password",
    "tcp-retransmissions": "TCP retransmissions",
}
NAIVE = {
    "port-scan": "15 different host:port targets in the whole capture",
    "beacon": "8 connections to one destination, however irregular",
    "nxdomain-storm": "5 names that do not exist",
    "dns-tunnel": "25 different names below one domain",
}


def rate(rows: list[dict], key: str) -> str:
    return " | ".join(f"{r[key]}" for r in rows)


def hits(rows: list[dict]) -> str:
    return " | ".join(f"{r['found']}/{r['of']}" for r in rows)


truth_rows = "\n".join(f"| {KINDS[k]} | {P['truth'][k]} | {P['found'].get(k, 0)} |" for k in KINDS)
base_rows = "\n".join(
    f"| {KINDS[k]}: {NAIVE[k]} | {BL['alerts'][k]} | {BL['false'][k]} | {Q['naive_alerts'].get(k, 0)} |" for k in NAIVE
)
cross_rows = ", ".join(f"{k} {v}" for k, v in X["by_kind"].items())
real_rows = "\n".join(
    f"| `{r['file']}` | {r['packets']} | {r['flows']} | {r['fields_equal']} | {r['fields_different']} | "
    f"{', '.join(r['tls_names']) or '-'} |"
    for r in R["rows"]
)


def sweep(name: str, key: str, label: str) -> str:
    rows = B[name]
    head = f"| {label} | " + " | ".join(str(r[key]) for r in rows) + " |"
    return (
        head
        + "\n|---|"
        + "---|" * len(rows)
        + "\n| injected things found | "
        + " | ".join(str(r["found"]) for r in rows)
        + " |"
        + "\n| false findings | "
        + " | ".join(str(r["false_findings"]) for r in rows)
        + " |"
    )


pc, ng = C["pcap"], C["pcapng"]


def cost_row(name: str, c: dict) -> str:
    return (
        f"| {name} | {c['packets']:,} | {c['file_mib']} MiB | {c['read']['packets_per_second']:,} | "
        f"{c['decode']['packets_per_second']:,} | {c['analyze']['packets_per_second']:,} | "
        f"{c['all']['packets_per_second']:,} | {c['all']['max_rss_mib']:g} MiB |"
    )


txt = f"""# Evaluation

Produced by `python tools/evaluate.py --real DIR --out docs/report.json` (machine: {E_["system"]}, Python {E_["python"]},
seed {E_["seed"]}; the run took {E_["seconds"]:g} s).

**What this is and is not.** There is no way to get a real network that attacks on command, so the accuracy numbers come
from captures whose content is known: `pcaplab.synth` builds the ordinary traffic of a small network (web, DNS, NTP,
ping, ARP) plus a few things that look odd but are harmless (a client that opens ten ports of a server, a monitor that
checks twelve service ports every five minutes, a CDN with many short names, a few typos, a client that polls at random
intervals), and injects scans, a DNS tunnel, a flood of names that do not exist, beacons, ARP spoofing, clear-text
logins and a lossy upload at recorded places. What was injected is written down by the generator, independently of the
detectors. This shows that the detectors do what they claim and where they stop. It does not show how often a real
network looks like the generator: see [limitations](limitations.md). Two things are measured on code and data that
the author did not write: the decoder against scapy (section 1) and against real captures (section 5).

The detectors' thresholds were set while looking at seeds 1 to 5. The numbers below use seeds from {E_["seed"]} on, which
were not looked at before the numbers were produced.

## 1. Is the decoder right?

scapy 2.6.1 builds {X["packets"]:,} random packets ({cross_rows}) with chosen field values; pcaplab reads the bytes and
every field is compared with what was put in ({X["fields_compared"]:,} fields: addresses, ports, flags, sequence numbers,
TTL, VLAN, ICMP type, DNS name, type, answers and response code, HTTP method, path and host, payload, link-layer
addresses).

**{X["mismatches"]} fields differ.**

## 2. Findings against what was injected

{P["captures"]} captures of {P["seconds_each"]:g} s each ({P["packets"]:,} packets) with the injected things, and {Q["captures"]} captures of
the same length without any attack ({Q["packets"]:,} packets, harmless oddities only).

| injected | count | found |
|---|---|---|
{truth_rows}
| **all** | **{P["truth_total"]}** | **{P["found_total"]}** |

- **False findings: {P["false_findings"]}** in the captures with attacks, **{Q["false_findings"]}** in the quiet ones. Two findings for one thing: {P["duplicates"]}.
- The slow scan (one probe every 20 s, injected {P["slow_scan"]["injected"]} times) was found {P["slow_scan"]["found"]} times, as the documented limit says.

Three rules a first script would use, on the same captures (alerts include the true ones):

| naive rule | alerts | of them false | alerts in the quiet captures |
|---|---|---|---|
{base_rows}

pcaplab's rules need what the naive ones leave out: the target never answering or the conversation carrying no data
(scans), regular gaps (beacons), a share of the client's answers (NXDOMAIN), and length and randomness of the names
(tunnels).

## 3. Where each detector stops

{B["scan_rate"][0]["of"]} runs per cell, a single injected event in an otherwise empty capture. Moving a threshold has a cost on both sides: the
last four tables run the full captures of section 2 (with their harmless oddities) at other thresholds.

**Scan speed** (200 ports; the rule needs 15 targets in 60 s, that is 0.25 probes per second)

| probes per second | {rate(B["scan_rate"], "probes_per_second")} |
|---|{"---|" * len(B["scan_rate"])}
| found | {hits(B["scan_rate"])} |

**Scan size** (at 20 probes per second)

| ports | {rate(B["scan_size"], "ports")} |
|---|{"---|" * len(B["scan_size"])}
| found | {hits(B["scan_size"])} |

**Beacon regularity** (30 connections, one a minute, random jitter of ± the given share)

| jitter | {rate(B["beacon_jitter"], "jitter")} |
|---|{"---|" * len(B["beacon_jitter"])}
| found | {hits(B["beacon_jitter"])} |

**Beacon length** (jitter 5%)

| connections | {rate(B["beacon_count"], "connections")} |
|---|{"---|" * len(B["beacon_count"])}
| found | {hits(B["beacon_count"])} |

**DNS tunnel size**

| names | {rate(B["tunnel_size"], "names")} |
|---|{"---|" * len(B["tunnel_size"])}
| found | {hits(B["tunnel_size"])} |

**Effect of the thresholds** on the full captures:

{sweep("sweep_scan_targets", "scan_targets", "scan targets (default 15)")}

{sweep("sweep_beacon_spread", "beacon_spread", "beacon spread (default 0.15)")}

{sweep("sweep_beacon_min", "beacon_min", "beacon connections (default 8)")}

{sweep("sweep_nx_names", "nx_names", "NXDOMAIN names (default 20)")}

## 4. Cost

One capture of the generator repeated to a larger file (the file sits on disk; each stage is a separate process, best of
three; peak memory is the high-water mark of the process).

| format | packets | file | read (packets/s) | + decode | + analyze | + detect | peak memory |
|---|---|---|---|---|---|---|---|
{cost_row("pcap", pc)}
{cost_row("pcapng", ng)}

Reading and decoding keep about {pc["decode"]["max_rss_mib"]:g} MiB whatever the size of the file. Analysis keeps one record per flow, about
{(pc["analyze"]["max_rss_mib"] - pc["decode"]["max_rss_mib"]) * 1024 / pc["analyze"]["flows"]:.1f} KiB each ({pc["analyze"]["flows"]:,} flows here, {pc["analyze"]["max_rss_mib"]:g} MiB in all): memory grows with the number of
conversations, not with the number of packets.

## 5. Captures taken by other people

{R["files"]} captures from the Wireshark test suite (`test/captures` in the wireshark/wireshark repository: DHCP in pcap, nanosecond
pcap and pcapng, DNS, mDNS and IPv6, HTTP, TLS 1.2 and 1.3, an ARP file in a link type pcaplab does not read). They are
not stored in this repository; `tools/evaluate.py --real DIR` reads whatever is in `DIR`. scapy reads the same files
and the fields it and pcaplab both have are compared (addresses, ports, TCP flags and sequence numbers, ICMP type, DNS
name).

pcaplab read {R["packets"]} packets, scapy {R["scapy_packets"]}; **{R["fields_equal"]:,} fields equal, {R["fields_different"]} different**;
{R["undecoded"]} packet could not be decoded (the Frame Relay file `arp.pcap`, link type 107).

| file | packets | flows | fields equal | different | TLS server names |
|---|---|---|---|---|---|
{real_rows}

No detector reported anything on these files, as expected for captures without attacks. They say nothing about
detection rates.
"""
Path("docs/evaluation.md").write_text(txt, encoding="utf-8")
print("wrote docs/evaluation.md")
