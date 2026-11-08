"""Measure pcaplab against captures whose content is known, and against real captures.

    python tools/evaluate.py                  # full run (a few minutes), prints a summary
    python tools/evaluate.py --quick          # smaller sets, used in CI
    python tools/evaluate.py --out docs/report.json
    python tools/evaluate.py --real DIR       # also read the real captures in DIR (see docs/evaluation.md)

Sections: crosscheck (the decoder against scapy, an implementation that shares no code with it), pipeline (findings
against what the generator injected, with three naive baselines), boundaries (where each detector stops seeing, and the
effect of the thresholds), cost (speed and memory), real (captures taken by other people).

Seeds: the thresholds of pcaplab were set while looking at seeds 1 to 5; this script uses other seeds (1000 and up),
which were not looked at before the numbers were produced.
"""

from __future__ import annotations

import argparse
import json
import platform
import random
import resource
import statistics
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "src"))

from pcaplab.analyze import Result, analyze_packets  # noqa: E402
from pcaplab.decode import decode  # noqa: E402
from pcaplab.detect import Thresholds, detect  # noqa: E402
from pcaplab.reader import CaptureReader  # noqa: E402
from pcaplab.synth import LAN, Frame, Traffic, Truth, build_scenario, pcap_bytes, pcapng_bytes  # noqa: E402
from score import score  # noqa: E402

SEED = 1000
SECTIONS = ("crosscheck", "pipeline", "boundaries", "cost", "real")


def analyze_frames(frames: list[Frame]) -> Result:
    with CaptureReader(pcap_bytes(sorted(frames, key=lambda f: f[0]))) as cap:
        return analyze_packets(cap)


# --- crosscheck ------------------------------------------------------------------------------------------------------


def section_crosscheck(quick: bool) -> dict[str, object]:
    """scapy builds packets with chosen field values; pcaplab reads the bytes; every field must come back."""
    try:
        import logging

        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
        from scapy.all import (  # type: ignore[import-not-found,unused-ignore]
            ARP,
            DNS,
            DNSQR,
            DNSRR,
            ICMP,
            IP,
            TCP,
            UDP,
            CookedLinux,
            Dot1Q,
            Ether,
            IPv6,
            Raw,
            raw,
            scapy,
        )
        from scapy.layers.inet6 import ICMPv6EchoRequest  # type: ignore[import-not-found,unused-ignore]
        from scapy.layers.l2 import CookedLinuxV2  # type: ignore[import-not-found,unused-ignore]
    except ImportError:
        return {"skipped": "scapy is not installed"}
    n = 2000 if quick else 20000
    rng = random.Random(SEED)
    counts: Counter[str] = Counter()
    fields = 0
    bad: list[str] = []

    def ip4() -> str:
        return ".".join(str(rng.randrange(1, 255)) for _ in range(4))

    def ip6() -> str:
        return ":".join(f"{rng.randrange(1, 65536):x}" for _ in range(8))

    def mac() -> str:
        return ":".join(f"{rng.randrange(256):02x}" for _ in range(6))

    def label() -> str:
        return (
            "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789-") for _ in range(rng.randint(1, 20))).strip("-")
            or "x"
        )

    def name() -> str:
        return ".".join(label() for _ in range(rng.randint(2, 5)))

    def check(kind: str, d: object, want: dict[str, object]) -> None:
        nonlocal fields
        for key, value in want.items():
            fields += 1
            got = d
            for part in key.split("."):
                got = getattr(got, part)
            if got != value:
                bad.append(f"{kind}.{key}: got {got!r}, want {value!r}")

    from pcaplab.model import Packet

    for i in range(n):
        kind = rng.choice(
            ["tcp4", "udp4", "icmp4", "tcp6", "udp6", "icmp6", "arp", "dns_q", "dns_r", "http", "vlan", "sll", "sll2"]
        )
        counts[kind] += 1
        e = Ether(src=mac(), dst=mac())
        payload = rng.randbytes(rng.randint(0, 300))
        sport, dport = rng.randrange(1, 65536), rng.randrange(1, 65536)
        a, b, ttl = ip4(), ip4(), rng.randrange(1, 256)
        want: dict[str, object]
        if kind == "tcp4":
            flags, seq, ack = rng.randrange(0, 64), rng.randrange(1 << 32), rng.randrange(1 << 32)
            win = rng.randrange(65536)
            pkt = (
                e
                / IP(src=a, dst=b, ttl=ttl)
                / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack, window=win)
                / Raw(payload)
            )
            want = {
                "proto": "tcp",
                "src": a,
                "dst": b,
                "ttl": ttl,
                "sport": sport,
                "dport": dport,
                "flags": flags,
                "seq": seq,
                "ack": ack,
                "win": win,
                "payload_len": len(payload),
            }
        elif kind == "vlan":
            vid = rng.randrange(1, 4095)
            pkt = e / Dot1Q(vlan=vid) / IP(src=a, dst=b, ttl=ttl) / UDP(sport=sport, dport=dport) / Raw(payload)
            want = {"proto": "udp", "vlan": vid, "src": a, "dst": b, "sport": sport, "dport": dport, "payload": payload}
        elif kind in ("sll", "sll2"):
            cooked = CookedLinux if kind == "sll" else CookedLinuxV2
            lladdr = bytes(rng.randrange(256) for _ in range(6)) + b"\x00\x00"
            pkt = (
                cooked(proto=0x800, lladdrlen=6, src=lladdr, lladdrtype=1, pkttype=0)
                / IP(src=a, dst=b, ttl=ttl)
                / UDP(sport=sport, dport=9999)
                / Raw(payload)
            )
            want = {
                "proto": "udp",
                "src": a,
                "dst": b,
                "sport": sport,
                "dport": 9999,
                "payload": payload,
                "eth_src": lladdr[:6].hex(":"),
            }
        elif kind == "udp4":
            sport = rng.choice([sport, 40000])
            dport = rng.choice([dport, 9999])  # not a DNS port: the payload is not DNS
            pkt = e / IP(src=a, dst=b, ttl=ttl) / UDP(sport=sport, dport=dport) / Raw(payload)
            want = {"proto": "udp", "src": a, "dst": b, "sport": sport, "dport": dport, "payload": payload}
        elif kind == "icmp4":
            t, c = rng.randrange(0, 20), rng.randrange(0, 16)
            pkt = e / IP(src=a, dst=b, ttl=ttl) / ICMP(type=t, code=c) / Raw(payload)
            want = {"proto": "icmp", "src": a, "dst": b, "icmp_type": t, "icmp_code": c}
        elif kind == "tcp6":
            s6, d6 = ip6(), ip6()
            flags, seq = rng.randrange(0, 64), rng.randrange(1 << 32)
            pkt = (
                e / IPv6(src=s6, dst=d6, hlim=ttl) / TCP(sport=sport, dport=dport, flags=flags, seq=seq) / Raw(payload)
            )
            want = {
                "proto": "tcp",
                "ip_version": 6,
                "src": _norm6(s6),
                "dst": _norm6(d6),
                "ttl": ttl,
                "sport": sport,
                "dport": dport,
                "flags": flags,
                "seq": seq,
                "payload_len": len(payload),
            }
        elif kind == "udp6":
            s6, d6 = ip6(), ip6()
            pkt = e / IPv6(src=s6, dst=d6) / UDP(sport=40000, dport=9999) / Raw(payload)
            want = {"proto": "udp", "ip_version": 6, "src": _norm6(s6), "dst": _norm6(d6), "payload": payload}
        elif kind == "icmp6":
            s6, d6 = ip6(), ip6()
            pkt = e / IPv6(src=s6, dst=d6) / ICMPv6EchoRequest()
            want = {"proto": "icmp6", "icmp_type": 128, "src": _norm6(s6), "dst": _norm6(d6)}
        elif kind == "arp":
            op = rng.choice([1, 2])
            sh, sp, th, tp = mac(), ip4(), mac(), ip4()
            pkt = e / ARP(op=op, hwsrc=sh, psrc=sp, hwdst=th, pdst=tp)
            want = {"proto": "arp", "arp.op": op, "arp.sha": sh, "arp.spa": sp, "arp.tha": th, "arp.tpa": tp}
        elif kind == "dns_q":
            qn, qt = name(), rng.choice([1, 28, 16, 15, 5, 2, 12])
            pkt = (
                e
                / IP(src=a, dst=b)
                / UDP(sport=sport, dport=53)
                / DNS(id=i % 65536, rd=1, qd=DNSQR(qname=qn, qtype=qt))
            )
            want = {"proto": "udp", "dns.id": i % 65536, "dns.qname": qn, "dns.qtype": qt, "dns.response": False}
        elif kind == "dns_r":
            qn, rc = name(), rng.choice([0, 0, 0, 2, 3, 5])
            ans = rng.randrange(1, 4)
            addrs = [ip4() for _ in range(ans)]
            rrs = DNSRR(rrname=qn, type="A", ttl=60, rdata=addrs[0])
            for x in addrs[1:]:
                rrs = rrs / DNSRR(rrname=qn, type="A", ttl=60, rdata=x)
            pkt = (
                e
                / IP(src=a, dst=b)
                / UDP(sport=53, dport=sport)
                / DNS(id=i % 65536, qr=1, rcode=rc, ancount=ans, qd=DNSQR(qname=qn), an=rrs)
            )
            want = {
                "dns.id": i % 65536,
                "dns.qname": qn,
                "dns.rcode": rc,
                "dns.response": True,
                "dns.answers": [(qn, 1, x) for x in addrs],
            }
        else:  # http
            host = name()
            path = "/" + "/".join(label() for _ in range(rng.randint(0, 3)))
            method = rng.choice(["GET", "POST", "PUT", "DELETE", "HEAD"])
            body = f"{method} {path}?q={label()} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: x\r\n\r\n".encode()
            pkt = e / IP(src=a, dst=b) / TCP(sport=sport, dport=80, flags="PA") / Raw(body)
            want = {"proto": "tcp", "http.method": method, "http.target": path, "http.host": host}
        data = raw(pkt)
        d = decode(Packet(i + 1, 0.0, len(data), {"sll": 113, "sll2": 276}.get(kind, 1), data))
        if d.error:
            bad.append(f"{kind}: decode error {d.error}")
            continue
        check(kind, d, want)
        if kind not in ("arp", "sll", "sll2"):
            check(kind, d, {"eth_src": pkt[Ether].src.lower(), "eth_dst": pkt[Ether].dst.lower()})
    return {
        "scapy": scapy.__version__ if hasattr(scapy, "__version__") else "",
        "packets": n,
        "by_kind": dict(sorted(counts.items())),
        "fields_compared": fields,
        "mismatches": len(bad),
        "first_mismatches": bad[:10],
    }


def _norm6(text: str) -> str:
    import ipaddress

    return ipaddress.IPv6Address(text).compressed


# --- pipeline --------------------------------------------------------------------------------------------------------

BASELINE = "naive"


def naive_alerts(r: Result) -> dict[str, set[str]]:
    """Rules a first script would use: counts without the conditions that make pcaplab's rules."""
    scan: dict[str, set[tuple[str, int]]] = {}
    seen: Counter[tuple[str, str, int]] = Counter()
    for f in r.flows:
        if f.proto == "tcp" and f.syn:
            scan.setdefault(f.a, set()).add((f.b, f.b_port))
            seen[(f.a, f.b, f.b_port)] += 1
    return {
        "port-scan": {h for h, t in scan.items() if len(t) >= 15},  # 15 targets, whatever happened and whenever
        "beacon": {k[0] for k, n in seen.items() if n >= 8},  # 8 connections to one place, however irregular
        "nxdomain-storm": {c for c, nx in r.nx.items() if len(nx.names) >= 5},  # 5 names that do not exist
        "dns-tunnel": {c for (c, _d), a in r.dns_agg.items() if a.unique >= 25},  # 25 names below one domain
    }


def section_pipeline(quick: bool) -> dict[str, object]:
    count = 8 if quick else 40
    quiet_count = 4 if quick else 15
    duration = 1800.0
    found: Counter[str] = Counter()
    total: Counter[str] = Counter()
    false_findings: list[str] = []
    duplicates = 0
    missed: list[str] = []
    slow = {"injected": 0, "found": 0}
    packets = 0
    base_alerts: Counter[str] = Counter()
    base_true: Counter[str] = Counter()
    base_false: Counter[str] = Counter()
    results: list[tuple[Result, list[Truth]]] = []
    for i in range(count):
        frames, truth = build_scenario(SEED + i, duration)
        r = analyze_frames(frames)
        packets += r.packets
        s = score(detect(r), truth)
        for k, v in s.total.items():
            total[k] += v
        for k, v in s.found.items():
            found[k] += v
        false_findings += [f"{f.kind} {f.hosts}" for f in s.false_findings]
        duplicates += s.duplicates
        missed += [f"{t.kind} {t.host}" for t in s.missed]
        slow["injected"] += s.expected_missed
        slow["found"] += s.unexpected_found
        truth_hosts = {(t.kind, t.host) for t in truth if t.detectable}
        for kind, hosts in naive_alerts(r).items():
            base_alerts[kind] += len(hosts)
            base_true[kind] += sum((kind, h) in truth_hosts for h in hosts)
            base_false[kind] += sum((kind, h) not in truth_hosts for h in hosts)
        results.append((r, truth))
    quiet_packets = 0
    quiet_false: list[str] = []
    quiet_base: Counter[str] = Counter()
    for i in range(quiet_count):
        frames, _ = build_scenario(SEED + 500 + i, duration, attacks=False)
        r = analyze_frames(frames)
        quiet_packets += r.packets
        quiet_false += [f"{f.kind} {f.hosts}" for f in detect(r)]
        for kind, hosts in naive_alerts(r).items():
            quiet_base[kind] += len(hosts)
    return {
        "captures": count,
        "seconds_each": duration,
        "packets": packets,
        "truth": dict(sorted(total.items())),
        "found": dict(sorted(found.items())),
        "found_total": sum(found.values()),
        "truth_total": sum(total.values()),
        "missed": missed,
        "false_findings": len(false_findings),
        "false_list": false_findings[:10],
        "duplicates": duplicates,
        "slow_scan": slow,
        "quiet": {
            "captures": quiet_count,
            "packets": quiet_packets,
            "false_findings": len(quiet_false),
            "naive_alerts": dict(sorted(quiet_base.items())),
        },
        "baseline": {
            "alerts": dict(sorted(base_alerts.items())),
            "true": dict(sorted(base_true.items())),
            "false": dict(sorted(base_false.items())),
        },
    }


# --- boundaries ------------------------------------------------------------------------------------------------------


def one(tr: Traffic, th: Thresholds | None = None) -> list[str]:
    return [f.kind for f in detect(analyze_frames(tr.frames), th)]


def section_boundaries(quick: bool) -> dict[str, object]:
    reps = 3 if quick else 8
    out: dict[str, object] = {}

    rows = []
    for rate in (0.1, 0.2, 0.3, 0.5, 1, 5, 50):
        hit = 0
        for s in range(reps):
            tr = Traffic(SEED + s)
            tr.syn_scan("203.0.113.50", [f"{LAN}5"], list(range(1, 201)), 100.0, rate)
            hit += "port-scan" in one(tr)
        rows.append({"probes_per_second": rate, "found": hit, "of": reps})
    out["scan_rate"] = rows

    rows = []
    for ports in (5, 10, 14, 15, 16, 30, 100):
        hit = 0
        for s in range(reps):
            tr = Traffic(SEED + s)
            tr.syn_scan("203.0.113.50", [f"{LAN}5"], list(range(1, ports + 1)), 100.0, 20)
            hit += "port-scan" in one(tr)
        rows.append({"ports": ports, "found": hit, "of": reps})
    out["scan_size"] = rows

    rows = []
    for jitter in (0.0, 0.05, 0.1, 0.2, 0.3, 0.5, 0.8):
        hit = 0
        for s in range(reps):
            tr = Traffic(SEED + s)
            tr.beacon(f"{LAN}45", "192.0.2.77", 443, 100.0, 60.0, 30, jitter)
            hit += "beacon" in one(tr)
        rows.append({"jitter": jitter, "found": hit, "of": reps})
    out["beacon_jitter"] = rows

    rows = []
    for n in (5, 7, 8, 12, 30):
        hit = 0
        for s in range(reps):
            tr = Traffic(SEED + s)
            tr.beacon(f"{LAN}45", "192.0.2.77", 443, 100.0, 60.0, n, 0.05)
            hit += "beacon" in one(tr)
        rows.append({"connections": n, "found": hit, "of": reps})
    out["beacon_count"] = rows

    rows = []
    for n in (10, 20, 24, 25, 40, 100):
        hit = 0
        for s in range(reps):
            tr = Traffic(SEED + s)
            tr.dns_tunnel(f"{LAN}23", "t.bad.example.org", 100.0, n)
            hit += "dns-tunnel" in one(tr)
        rows.append({"names": n, "found": hit, "of": reps})
    out["tunnel_size"] = rows

    # the thresholds, on the full scenario captures: what they cost in misses and in false alarms
    sets = []
    for i in range(3 if quick else 10):
        frames, truth = build_scenario(SEED + 800 + i, 1800.0)
        sets.append((analyze_frames(frames), truth))

    def sweep(name: str, values: list[float], make: object) -> list[dict[str, object]]:
        table = []
        for v in values:
            f_ok = missed = false = 0
            for r, truth in sets:
                s = score(detect(r, make(v)), truth)  # type: ignore[operator]
                f_ok += sum(s.found.values())
                missed += len(s.missed)
                false += len(s.false_findings)
            table.append({name: v, "found": f_ok, "missed": missed, "false_findings": false})
        return table

    out["sweep_scan_targets"] = sweep("scan_targets", [5, 10, 15, 25, 40], lambda v: Thresholds(scan_targets=int(v)))
    out["sweep_beacon_spread"] = sweep(
        "beacon_spread", [0.02, 0.05, 0.15, 0.4, 0.8], lambda v: Thresholds(beacon_spread=v)
    )
    out["sweep_beacon_min"] = sweep("beacon_min", [3, 5, 8, 12, 20], lambda v: Thresholds(beacon_min=int(v)))
    out["sweep_nx_names"] = sweep("nx_names", [3, 5, 10, 20, 40], lambda v: Thresholds(nx_names=int(v)))
    return out


# --- cost ------------------------------------------------------------------------------------------------------------

_CHILD = """
import resource, sys, time
sys.path.insert(0, {src!r})
from pcaplab.reader import CaptureReader
from pcaplab.decode import decode
from pcaplab.analyze import analyze_packets
from pcaplab.detect import detect


def peak_mib():
    try:  # the high-water mark of this process; ru_maxrss would carry what the parent had before exec
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("VmHWM:"):
                    return int(line.split()[1]) / 1024
    except OSError:
        pass
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / (1048576 if sys.platform == "darwin" else 1024)


mode, path = sys.argv[1], sys.argv[2]
t = time.perf_counter()
n = flows = 0
with CaptureReader(path) as cap:
    if mode == "read":
        for p in cap:
            n += 1
    elif mode == "decode":
        for p in cap:
            decode(p)
            n += 1
    else:
        r = analyze_packets(cap)
        n, flows = r.packets, len(r.flows)
        if mode == "all":
            detect(r)
dt = time.perf_counter() - t
print(n, dt, peak_mib(), flows)
"""


def big_capture(path: Path, copies: int, fmt: str) -> int:
    frames, _ = build_scenario(SEED, 1800.0)
    span = frames[-1][0] - frames[0][0] + 10
    all_frames: list[Frame] = []
    for c in range(copies):
        all_frames += [(t + c * span, d) for t, d in frames]
    path.write_bytes(pcapng_bytes(all_frames) if fmt == "pcapng" else pcap_bytes(all_frames))
    return len(all_frames)


def section_cost(quick: bool) -> dict[str, object]:
    copies = 3 if quick else 12
    out: dict[str, object] = {}
    with tempfile.TemporaryDirectory() as tmp:
        for fmt in ("pcap", "pcapng"):
            path = Path(tmp) / f"big.{fmt}"
            n = big_capture(path, copies, fmt)
            row: dict[str, object] = {"packets": n, "file_mib": round(path.stat().st_size / 2**20, 1)}
            for mode in ("read", "decode", "analyze", "all"):
                best = None
                for _ in range(3):
                    p = subprocess.run(
                        [sys.executable, "-I", "-c", _CHILD.format(src=str(ROOT / "src")), mode, str(path)],
                        capture_output=True,
                        text=True,
                        check=True,
                    )
                    _, dt, rss, flows = p.stdout.split()
                    rec = (float(dt), float(rss), int(flows))
                    best = rec if best is None or rec[0] < best[0] else best
                assert best is not None
                row[mode] = {
                    "packets_per_second": round(n / best[0]),
                    "seconds": round(best[0], 2),
                    "max_rss_mib": round(best[1], 1),
                    "flows": best[2],
                }
            out[fmt] = row
    return out


# --- real ------------------------------------------------------------------------------------------------------------


def section_real(real: Path | None) -> dict[str, object]:
    if real is None:
        return {"skipped": "no --real directory given"}
    try:
        import logging

        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
        from scapy.all import (  # type: ignore[import-not-found,unused-ignore]
            ARP,
            DNS,
            ICMP,
            IP,
            TCP,
            UDP,
            IPv6,
            rdpcap,
        )
    except ImportError:
        return {"skipped": "scapy is not installed"}
    files = sorted(p for p in real.iterdir() if p.suffix in (".pcap", ".pcapng"))
    rows = []
    tot = Counter()
    for path in files:
        with CaptureReader(path) as cap:
            ours = [decode(p) for p in cap]
            warn = list(cap.warnings)
        theirs = list(rdpcap(str(path)))
        row = {
            "file": path.name,
            "packets": len(ours),
            "scapy_packets": len(theirs),
            "undecoded": sum(1 for d in ours if d.error),
            "warnings": warn,
        }
        same = diff = skipped = 0
        for d, s in zip(ours, theirs, strict=False):
            if d.error:
                skipped += 1
                continue
            facts = []
            if s.haslayer(IP):
                facts.append((d.src, s[IP].src))
                facts.append((d.dst, s[IP].dst))
            elif s.haslayer(IPv6):
                facts.append((d.src, _norm6(s[IPv6].src)))
                facts.append((d.dst, _norm6(s[IPv6].dst)))
            elif s.haslayer(ARP):
                facts.append((d.arp.spa if d.arp else "", s[ARP].psrc))
            if s.haslayer(TCP):
                facts += [
                    (d.proto, "tcp"),
                    (d.sport, s[TCP].sport),
                    (d.dport, s[TCP].dport),
                    (d.seq, s[TCP].seq),
                    (d.flags, int(s[TCP].flags) & 0x3F),
                ]
            elif s.haslayer(UDP):
                facts += [(d.proto, "udp"), (d.sport, s[UDP].sport), (d.dport, s[UDP].dport)]
            elif s.haslayer(ICMP):
                facts += [(d.proto, "icmp"), (d.icmp_type, s[ICMP].type)]
            if s.haslayer(DNS) and s[DNS].qd is not None and d.dns:
                qn = (
                    s[DNS].qd.qname.decode("latin-1").rstrip(".").lower()
                    if isinstance(s[DNS].qd.qname, bytes)
                    else str(s[DNS].qd.qname).rstrip(".").lower()
                )
                facts.append((d.dns.qname, qn))
            for a, b in facts:
                if a == b:
                    same += 1
                else:
                    diff += 1
        row.update({"fields_equal": same, "fields_different": diff, "packets_not_decoded_by_pcaplab": skipped})
        r = analyze_packets(CaptureReader(path))
        row["flows"] = len(r.flows)
        row["findings"] = [f.kind for f in detect(r)]
        row["tls_names"] = sorted(r.sni)
        rows.append(row)
        tot["packets"] += len(ours)
        tot["scapy_packets"] += len(theirs)
        tot["same"] += same
        tot["diff"] += diff
        tot["undecoded"] += int(row["undecoded"])  # type: ignore[call-overload]
    return {
        "files": len(files),
        "packets": tot["packets"],
        "scapy_packets": tot["scapy_packets"],
        "fields_equal": tot["same"],
        "fields_different": tot["diff"],
        "undecoded": tot["undecoded"],
        "rows": rows,
    }


# --- main ------------------------------------------------------------------------------------------------------------


def summary(rep: dict[str, object]) -> list[str]:
    lines = []
    x = rep.get("crosscheck")
    if isinstance(x, dict) and "packets" in x:
        lines.append(
            f"crosscheck: {x['packets']} packets, {x['fields_compared']} fields compared with scapy, {x['mismatches']} different"
        )
    p = rep.get("pipeline")
    if isinstance(p, dict):
        lines.append(
            f"pipeline: {p['found_total']} of {p['truth_total']} injected things found, {p['false_findings']} false findings, "
            f"{p['duplicates']} duplicates, quiet captures: {p['quiet']['false_findings']} false findings"  # type: ignore[index]
        )
        lines.append(f"  naive rules: {p['baseline']['alerts']} alerts ({p['baseline']['false']} false)")  # type: ignore[index]
    c = rep.get("cost")
    if isinstance(c, dict):
        for fmt, row in c.items():
            lines.append(
                f"cost {fmt}: {row['packets']} packets; read {row['read']['packets_per_second']}/s, decode {row['decode']['packets_per_second']}/s, analyze {row['analyze']['packets_per_second']}/s, all {row['all']['packets_per_second']}/s, {row['all']['max_rss_mib']:.0f} MiB"
            )
    r = rep.get("real")
    if isinstance(r, dict) and "files" in r:
        lines.append(
            f"real: {r['files']} files, {r['packets']} packets (scapy {r['scapy_packets']}), {r['fields_equal']} fields equal, {r['fields_different']} different, {r['undecoded']} not decoded"
        )
    return lines


def check(rep: dict[str, object]) -> list[str]:
    bad = []
    x = rep.get("crosscheck")
    if isinstance(x, dict) and "mismatches" in x and x["mismatches"]:
        bad.append(f"crosscheck: {x['mismatches']} fields differ from scapy: {x['first_mismatches']}")
    p = rep.get("pipeline")
    if isinstance(p, dict):
        if p["found_total"] != p["truth_total"]:
            bad.append(f"pipeline: missed {p['missed']}")
        if p["false_findings"] or p["duplicates"] or p["quiet"]["false_findings"]:  # type: ignore[index]
            bad.append(f"pipeline: false findings {p['false_list']}, quiet {p['quiet']}")
        if p["slow_scan"]["found"]:  # type: ignore[index]
            bad.append("pipeline: the slow scan was found, so the documented limit is wrong")
    r = rep.get("real")
    if isinstance(r, dict) and "files" in r and (r["fields_different"] or r["packets"] != r["scapy_packets"]):
        bad.append("real: pcaplab and scapy disagree")
    return bad


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--only", default=",".join(SECTIONS))
    ap.add_argument("--out", type=Path)
    ap.add_argument("--real", type=Path, help="a directory with captures taken by other people")
    ap.add_argument("--check", action="store_true", help="exit 1 if the numbers break the expectations")
    args = ap.parse_args()
    want = set(args.only.split(","))
    rep: dict[str, object] = {
        "environment": {
            "system": f"{platform.system()} {platform.machine()}",
            "python": platform.python_version(),
            "seed": SEED,
            "quick": args.quick,
        }
    }
    t0 = time.perf_counter()
    if "crosscheck" in want:
        rep["crosscheck"] = section_crosscheck(args.quick)
    if "pipeline" in want:
        rep["pipeline"] = section_pipeline(args.quick)
    if "boundaries" in want:
        rep["boundaries"] = section_boundaries(args.quick)
    if "cost" in want:
        rep["cost"] = section_cost(args.quick)
    if "real" in want:
        rep["real"] = section_real(args.real)
    rep["environment"]["seconds"] = round(time.perf_counter() - t0, 1)  # type: ignore[index]
    if args.out:
        args.out.write_text(json.dumps(rep, indent=2) + "\n", encoding="utf-8")
    for line in summary(rep):
        print(line)
    bad = check(rep) if args.check else []
    for line in bad:
        print("FAIL:", line, file=sys.stderr)
    _ = statistics, resource  # kept for the notebooks that import this module
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
