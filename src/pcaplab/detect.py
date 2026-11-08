"""What looks wrong in a capture. Each detector reads the result of one pass and returns findings with the numbers
behind them, so a finding can be checked by hand. Thresholds are in ``Thresholds`` and can be changed."""

from __future__ import annotations

import statistics
from collections import Counter
from dataclasses import dataclass, field
from itertools import pairwise

from .analyze import Result
from .flows import Flow
from .model import fmt_dur

SEVERITIES = ("info", "low", "medium", "high")


@dataclass
class Thresholds:
    scan_targets: int = 15  # distinct host:port pairs probed without a conversation ...
    scan_window: float = 60.0  # ... within this many seconds
    dns_unique: int = 25  # distinct names asked below one domain by one client
    dns_mean_len: float = 18.0  # mean length of the part of the name below the domain
    dns_entropy: float = 3.3  # mean entropy of those parts, bits per character
    nx_names: int = 20  # distinct names that did not exist, for one client
    nx_ratio: float = 0.3  # and at least this share of its answers
    beacon_min: int = 8  # connections to the same destination
    beacon_spread: float = 0.15  # median absolute deviation of the gaps / median gap
    beacon_min_gap: float = 5.0  # seconds: faster than this is a burst, not a beacon
    beacon_ignore_ports: frozenset[int] = frozenset({53, 67, 68, 123, 137, 138, 1900, 5353})
    retrans_min: int = 10
    retrans_ratio: float = 0.05
    allow_hosts: frozenset[str] = frozenset()  # scanners, monitors and the like that are expected
    ignore_domains: frozenset[str] = frozenset()


@dataclass
class Finding:
    kind: str
    severity: str
    title: str
    detail: str
    hosts: tuple[str, ...]
    first: float
    last: float
    evidence: dict[str, object] = field(default_factory=dict)


def detect(r: Result, th: Thresholds | None = None) -> list[Finding]:
    th = th or Thresholds()
    found = [
        *port_scans(r, th),
        *dns_tunnels(r, th),
        *nxdomain_storms(r, th),
        *beacons(r, th),
        *arp_conflicts(r),
        *cleartext(r),
        *tcp_trouble(r, th),
    ]
    found.sort(key=lambda f: (-SEVERITIES.index(f.severity), f.first, f.kind))
    return found


# port scans ---------------------------------------------------------------------------------------------------


def _is_probe(f: Flow) -> bool:
    """A TCP connection attempt that never became a conversation: no answer, a refusal, no final ACK, or a handshake
    closed at once without a byte of data."""
    if f.proto != "tcp" or not f.syn or f.data[0] or f.data[1]:
        return False
    if f.state in ("unanswered", "refused", "half-open"):
        return True
    return f.duration <= 1.0


def port_scans(r: Result, th: Thresholds) -> list[Finding]:
    by_src: dict[str, list[Flow]] = {}
    for f in r.flows:
        if f.a not in th.allow_hosts and _is_probe(f):
            by_src.setdefault(f.a, []).append(f)
    out: list[Finding] = []
    for src, flows in by_src.items():
        flows.sort(key=lambda f: f.first)
        i = 0
        while i < len(flows):
            window: Counter[tuple[str, int]] = Counter()
            j = i
            hit = False
            for k in range(i, len(flows)):
                while flows[k].first - flows[j].first > th.scan_window:
                    key = (flows[j].b, flows[j].b_port)
                    window[key] -= 1
                    if not window[key]:
                        del window[key]
                    j += 1
                window[(flows[k].b, flows[k].b_port)] += 1
                if len(window) >= th.scan_targets:
                    hit = True
                    break
            if not hit:
                break
            end = k
            while end + 1 < len(flows) and flows[end + 1].first - flows[end].first <= th.scan_window:
                end += 1
            out.append(_scan_finding(src, flows[j : end + 1]))
            i = end + 1
    return out


def _scan_finding(src: str, flows: list[Flow]) -> Finding:
    hosts = Counter(f.b for f in flows)
    ports = {f.b_port for f in flows}
    targets = {(f.b, f.b_port) for f in flows}
    answered = sorted({(f.b, f.b_port) for f in flows if f.synack})
    first, last = flows[0].first, max(f.last for f in flows)
    if len(hosts) == 1:
        shape = f"{len(ports)} ports on {next(iter(hosts))}"
    elif len(ports) <= 3:
        shape = f"{'port' if len(ports) == 1 else 'ports'} {', '.join(map(str, sorted(ports)))} on {len(hosts)} hosts"
    else:
        shape = f"{len(ports)} ports on {len(hosts)} hosts"
    kind = "vertical" if len(hosts) == 1 else "horizontal" if len(ports) <= 3 else "block"
    open_part = f"{len(answered)} answered (open)" if answered else "none answered"
    return Finding(
        "port-scan",
        "medium",
        f"TCP port scan from {src}",
        f"{len(targets)} connection attempts that never became a conversation: {shape}, in {fmt_dur(last - first)}; "
        f"{open_part}",
        (src,),
        first,
        last,
        {
            "scanner": src,
            "shape": kind,
            "targets": len(targets),
            "hosts": len(hosts),
            "ports": len(ports),
            "open": [f"{h}:{p}" for h, p in answered[:20]],
            "seconds": round(last - first, 3),
        },
    )


# DNS ----------------------------------------------------------------------------------------------------------


def dns_tunnels(r: Result, th: Thresholds) -> list[Finding]:
    out: list[Finding] = []
    for agg in r.dns_agg.values():
        if agg.domain in th.ignore_domains or agg.client in th.allow_hosts:
            continue
        if agg.unique >= th.dns_unique and agg.mean_len >= th.dns_mean_len and agg.mean_entropy >= th.dns_entropy:
            sample = next(iter(agg.subs))[:48]
            out.append(
                Finding(
                    "dns-tunnel",
                    "high",
                    f"Possible DNS tunnel: {agg.client} to {agg.domain}",
                    f"{agg.unique} different names below {agg.domain}, {agg.mean_len:.0f} characters long on average and "
                    f"random-looking ({agg.mean_entropy:.2f} bits per character); first one: {sample}",
                    (agg.client,),
                    agg.first,
                    agg.last,
                    {
                        "client": agg.client,
                        "domain": agg.domain,
                        "names": agg.unique,
                        "queries": agg.queries,
                        "mean_length": round(agg.mean_len, 1),
                        "entropy": round(agg.mean_entropy, 2),
                        "txt_share": round(agg.txt_queries / agg.queries, 2) if agg.queries else 0.0,
                    },
                )
            )
    return out


def nxdomain_storms(r: Result, th: Thresholds) -> list[Finding]:
    out: list[Finding] = []
    for client, nx in r.nx.items():
        if client in th.allow_hosts or len(nx.names) < th.nx_names:
            continue
        if len(nx.names) / nx.responses < th.nx_ratio:
            continue
        sample = ", ".join(sorted(nx.names)[:3])
        out.append(
            Finding(
                "nxdomain-storm",
                "medium",
                f"Many names that do not exist, asked by {client}",
                f"{len(nx.names)} different names answered NXDOMAIN, out of {nx.responses} answers "
                f"({100 * len(nx.names) / nx.responses:.0f}%): a domain generation algorithm or a broken client. e.g. {sample}",
                (client,),
                nx.first,
                nx.last,
                {"client": client, "nxdomain_names": len(nx.names), "answers": nx.responses},
            )
        )
    return out


# beacons ------------------------------------------------------------------------------------------------------


def beacons(r: Result, th: Thresholds) -> list[Finding]:
    groups: dict[tuple[str, str, int, str], list[Flow]] = {}
    for f in r.flows:
        if f.a in th.allow_hosts or f.b_port in th.beacon_ignore_ports or f.proto not in ("tcp", "udp"):
            continue
        if f.proto == "tcp" and not f.syn:
            continue
        groups.setdefault((f.a, f.b, f.b_port, f.proto), []).append(f)
    out: list[Finding] = []
    for (src, dst, port, proto), flows in groups.items():
        starts: list[float] = []
        for t in sorted(f.first for f in flows):
            if not starts or t - starts[-1] >= 1.0:  # a retry within a second is the same beat
                starts.append(t)
        if len(starts) < th.beacon_min:
            continue
        gaps = [b - a for a, b in pairwise(starts)]
        med = statistics.median(gaps)
        if med < th.beacon_min_gap:
            continue
        mad = statistics.median(abs(g - med) for g in gaps)
        near = sum(abs(g - med) <= 0.3 * med for g in gaps) / len(gaps)
        if mad / med > th.beacon_spread or near < 0.8:
            continue
        sizes = [f.total_bytes for f in flows]
        out.append(
            Finding(
                "beacon",
                "medium",
                f"Regular connections from {src} to {dst}:{port}",
                f"{len(starts)} {proto.upper()} connections every {fmt_dur(med)} (spread {100 * mad / med:.0f}%), over "
                f"{fmt_dur(starts[-1] - starts[0])}; {statistics.median(sizes):.0f} bytes each: the pattern of a program "
                "calling home, or of a monitor",
                (src, dst),
                starts[0],
                starts[-1],
                {
                    "src": src,
                    "dst": dst,
                    "port": port,
                    "proto": proto,
                    "connections": len(starts),
                    "interval_s": round(med, 2),
                    "spread": round(mad / med, 3),
                    "median_bytes": statistics.median(sizes),
                },
            )
        )
    return out


# ARP ----------------------------------------------------------------------------------------------------------


def arp_conflicts(r: Result) -> list[Finding]:
    out: list[Finding] = []
    for ip, log in r.arp.items():
        macs = list(dict.fromkeys(c.mac for c in log))
        if len(macs) < 2:
            continue
        flipping = len(log) > len(macs)  # an owner came back: two machines are fighting for the address
        mismatches = sum(1 for _, a, _, _ in r.arp_mismatch if a == ip)
        out.append(
            Finding(
                "arp-conflict",
                "high" if flipping else "medium",
                f"{ip} is claimed by {len(macs)} different MAC addresses",
                f"owners in order: {' -> '.join(c.mac for c in log[:4])}{' -> ...' if len(log) > 4 else ''} ({len(log) - 1} changes); "
                + ("it goes back and forth: a duplicate address or ARP spoofing" if flipping else "the address moved")
                + (f"; {mismatches} replies came from a different MAC than they announce" if mismatches else ""),
                (ip,),
                log[0].ts,
                log[-1].ts,
                {"ip": ip, "macs": macs, "changes": len(log) - 1, "flipping": flipping},
            )
        )
    return out


# clear-text secrets -------------------------------------------------------------------------------------------


def cleartext(r: Result) -> list[Finding]:
    out: list[Finding] = []
    for hit in r.creds[:50]:
        if hit.kind == "http-basic":
            what, extra = "HTTP Basic login", f" for user {hit.user!r}" if hit.user else ""
        else:
            what, extra = "FTP password", ""
        out.append(
            Finding(
                "cleartext-credentials",
                "high",
                f"{what} sent in clear from {hit.src}",
                f"{what}{extra} to {hit.dst}:{hit.port}; anyone on the path can read it (the secret itself is not kept)",
                (hit.src, hit.dst),
                hit.ts,
                hit.ts,
                {"kind": hit.kind, "src": hit.src, "dst": hit.dst, "port": hit.port, "user": hit.user},
            )
        )
    return out


# TCP health ---------------------------------------------------------------------------------------------------


def tcp_trouble(r: Result, th: Thresholds) -> list[Finding]:
    bad = [f for f in r.flows if f.retrans >= th.retrans_min and f.retrans_ratio >= th.retrans_ratio]
    bad.sort(key=lambda f: -f.retrans)
    out: list[Finding] = []
    for f in bad[:10]:
        out.append(
            Finding(
                "tcp-retransmissions",
                "low",
                f"Segments sent again: {f.a}:{f.a_port} to {f.b}:{f.b_port}",
                f"{f.retrans} of {f.data_segments} data segments were repeated or out of order "
                f"({100 * f.retrans_ratio:.0f}%): loss or congestion on the path",
                (f.a, f.b),
                f.first,
                f.last,
                {
                    "flow": f"{f.a}:{f.a_port}-{f.b}:{f.b_port}",
                    "retransmissions": f.retrans,
                    "segments": f.data_segments,
                    "ratio": round(f.retrans_ratio, 3),
                },
            )
        )
    return out
