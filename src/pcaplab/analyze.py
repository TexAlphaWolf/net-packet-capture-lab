"""One pass over a capture: counts, hosts, flows and the facts the detectors need (DNS, ARP, clear-text logins)."""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from .decode import Decoded, decode
from .flows import Flow, FlowTable
from .model import Packet

MAX_NAMES = 5000  # per client and domain: the memory spent on one noisy host is bounded
MAX_ITEMS = 2000


def registered_domain(name: str) -> str:
    """The last two labels, or three under a two-letter country code with a generic second level (example.co.uk).
    Not the public suffix list: good enough to group the names a client asks for."""
    labels = name.split(".")
    if len(labels) <= 2:
        return name
    if len(labels[-1]) == 2 and labels[-2] in ("co", "com", "org", "net", "gov", "ac", "edu") and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def entropy(text: str) -> float:
    """Shannon entropy in bits per character."""
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


@dataclass(slots=True)
class DnsAgg:
    """What one client asked below one domain."""

    client: str
    domain: str
    queries: int = 0
    txt_queries: int = 0
    first: float = 0.0
    last: float = 0.0
    subs: dict[str, float] = field(default_factory=dict)  # distinct names below the domain -> entropy (bits/char)

    @property
    def unique(self) -> int:
        return len(self.subs)

    @property
    def mean_len(self) -> float:
        return sum(len(s) for s in self.subs) / len(self.subs) if self.subs else 0.0

    @property
    def mean_entropy(self) -> float:
        return sum(self.subs.values()) / len(self.subs) if self.subs else 0.0


@dataclass(slots=True)
class NxAgg:
    names: set[str] = field(default_factory=set)
    responses: int = 0
    first: float = 0.0
    last: float = 0.0


@dataclass(slots=True)
class CredHit:
    ts: float
    kind: str  # "http-basic", "ftp"
    src: str
    dst: str
    port: int
    user: str


@dataclass(slots=True)
class ArpChange:
    ts: float
    mac: str


@dataclass
class Result:
    packets: int = 0
    bytes: int = 0
    first: float = 0.0
    last: float = 0.0
    errors: Counter[str] = field(default_factory=Counter)
    kinds: Counter[str] = field(default_factory=Counter)  # packets by protocol
    apps: Counter[str] = field(default_factory=Counter)  # packets that carry dns / http / tls hello
    hosts: dict[str, list[int]] = field(default_factory=dict)  # ip -> [pkts out, bytes out, pkts in, bytes in]
    timeline: dict[int, list[int]] = field(default_factory=dict)  # second -> [packets, bytes]
    flows: list[Flow] = field(default_factory=list)
    dropped_flows: int = 0
    dns_queries: Counter[str] = field(default_factory=Counter)
    dns_rcodes: Counter[str] = field(default_factory=Counter)
    dns_agg: dict[tuple[str, str], DnsAgg] = field(default_factory=dict)
    nx: dict[str, NxAgg] = field(default_factory=dict)
    sni: Counter[str] = field(default_factory=Counter)
    http_hosts: Counter[str] = field(default_factory=Counter)
    arp: dict[str, list[ArpChange]] = field(default_factory=dict)  # ip -> successive owners (MAC)
    arp_mismatch: list[tuple[float, str, str, str]] = field(default_factory=list)  # (ts, ip, ethernet src, arp sha)
    creds: list[CredHit] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def duration(self) -> float:
        return max(0.0, self.last - self.first)


class Analyzer:
    def __init__(self, max_flows: int = 1_000_000) -> None:
        self.r = Result()
        self.table = FlowTable(max_flows)
        self._seen_creds: set[tuple[str, str, str, str]] = set()

    def feed(self, d: Decoded) -> None:
        r = self.r
        if r.packets == 0:
            r.first = r.last = d.ts
        r.packets += 1
        r.bytes += d.wirelen
        r.first, r.last = min(r.first, d.ts), max(r.last, d.ts)
        bucket = r.timeline.setdefault(int(d.ts), [0, 0])
        bucket[0] += 1
        bucket[1] += d.wirelen
        if d.error:
            r.errors[d.error] += 1
        r.kinds[d.proto or ("malformed" if d.error else "non-ip")] += 1
        if d.is_ip:
            out = r.hosts.setdefault(d.src, [0, 0, 0, 0])
            out[0] += 1
            out[1] += d.wirelen
            inc = r.hosts.setdefault(d.dst, [0, 0, 0, 0])
            inc[2] += 1
            inc[3] += d.wirelen
        self.table.add(d)
        if d.arp:
            self._arp(d)
        if d.dns:
            self._dns(d)
        if d.sni:
            r.apps["tls"] += 1
            r.sni[d.sni] += 1
        if d.http:
            r.apps["http"] += 1
            if d.http.host:
                r.http_hosts[d.http.host] += 1
            if d.http.is_request and d.http.auth_scheme == "basic":
                self._cred(d, "http-basic", d.http.auth_user)
        if d.proto == "tcp" and d.dport == 21 and d.payload.startswith(b"PASS "):
            self._cred(d, "ftp", "")

    def _cred(self, d: Decoded, kind: str, user: str) -> None:
        key = (kind, d.src, d.dst, user)
        if key not in self._seen_creds and len(self.r.creds) < MAX_ITEMS:
            self._seen_creds.add(key)
            self.r.creds.append(CredHit(d.ts, kind, d.src, d.dst, d.dport, user))

    def _arp(self, d: Decoded) -> None:
        a = d.arp
        assert a is not None
        if a.spa != "0.0.0.0":  # an address probe says who asks, not who owns the address
            log = self.r.arp.setdefault(a.spa, [])
            if (not log or log[-1].mac != a.sha) and len(log) < 50:
                log.append(ArpChange(d.ts, a.sha))
            if d.eth_src and d.eth_src != a.sha and len(self.r.arp_mismatch) < MAX_ITEMS:
                self.r.arp_mismatch.append((d.ts, a.spa, d.eth_src, a.sha))

    def _dns(self, d: Decoded) -> None:
        r = self.r
        m = d.dns
        assert m is not None
        r.apps["dns"] += 1
        name = m.qname
        if not m.response:
            r.dns_queries[name] += 1
            client = d.src
            dom = registered_domain(name)
            key = (client, dom)
            agg = r.dns_agg.get(key)
            if agg is None:
                if len(r.dns_agg) >= 50_000:
                    return
                agg = r.dns_agg[key] = DnsAgg(client, dom, first=d.ts)
            agg.queries += 1
            agg.last = d.ts
            if m.qtype == 16:
                agg.txt_queries += 1
            sub = name[: -len(dom) - 1] if name.endswith("." + dom) else ""
            if sub and sub not in agg.subs and len(agg.subs) < MAX_NAMES:
                agg.subs[sub] = entropy(sub.replace(".", ""))
        else:
            r.dns_rcodes[m.rcode_name] += 1
            client = d.dst
            nx = r.nx.setdefault(client, NxAgg(first=d.ts))
            nx.responses += 1
            nx.last = d.ts
            if m.rcode == 3 and len(nx.names) < MAX_NAMES:
                nx.names.add(name)

    def result(self) -> Result:
        r = self.r
        r.flows = self.table.all()
        r.dropped_flows = self.table.dropped
        return r


def analyze_packets(
    packets: Iterable[Packet],
    keep: Callable[[Decoded], bool] | None = None,
    *,
    max_flows: int = 1_000_000,
) -> Result:
    """Decode and analyse packets; ``keep`` (a compiled filter) drops the ones that do not match."""
    an = Analyzer(max_flows)
    for pkt in packets:
        d = decode(pkt)
        if keep is None or keep(d):
            an.feed(d)
    return an.result()
