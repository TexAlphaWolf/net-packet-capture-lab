"""Flows: the packets between two endpoints, with what a TCP conversation shows (handshake, resets, retransmissions)."""

from __future__ import annotations

from dataclasses import dataclass, field

from .decode import ACK, FIN, RST, SYN, Decoded
from .model import SERVICES

_MASK = 0xFFFFFFFF


@dataclass(slots=True)
class Flow:
    """One conversation. ``a`` is who sent the first packet (for TCP: the first SYN), ``b`` the other side.
    Lists hold [a to b, b to a]."""

    proto: str
    a: str
    a_port: int
    b: str
    b_port: int
    first: float
    last: float
    pkts: list[int] = field(default_factory=lambda: [0, 0])
    bytes: list[int] = field(default_factory=lambda: [0, 0])
    data: list[int] = field(default_factory=lambda: [0, 0])  # payload bytes
    syn: int = 0  # SYN (without ACK) sent by a
    synack: bool = False
    acked: bool = False  # a answered the SYN-ACK: the handshake is complete
    fin: int = 0
    rst_a: bool = False
    rst_b: bool = False
    retrans: int = 0  # segments sent again (or arriving out of order)
    data_segments: int = 0
    rtt: float | None = None  # SYN to SYN-ACK, in seconds
    syn_ts: float = 0.0
    names: set[str] = field(default_factory=set)  # TLS server name, HTTP host, DNS name seen in the flow
    hi_seq: list[int | None] = field(default_factory=lambda: [None, None])

    @property
    def duration(self) -> float:
        return self.last - self.first

    @property
    def total_bytes(self) -> int:
        return self.bytes[0] + self.bytes[1]

    @property
    def total_pkts(self) -> int:
        return self.pkts[0] + self.pkts[1]

    @property
    def state(self) -> str:
        if self.proto == "tcp":
            if not self.syn:
                return "reset" if self.rst_a or self.rst_b else "midstream"
            if not self.synack:
                return "refused" if self.rst_b else "unanswered"
            if not self.acked:
                return "half-open"
            if self.rst_a or self.rst_b:
                return "reset"
            return "closed" if self.fin else "established"
        return "answered" if self.pkts[1] else "one-way"

    @property
    def service(self) -> str:
        """A label for the traffic: the name of the server port, or the protocol when there is none."""
        if self.proto in ("tcp", "udp"):
            for port in (self.b_port, self.a_port):
                if port in SERVICES:
                    return SERVICES[port]
            return f"{self.proto}/{min(self.a_port, self.b_port) if min(self.a_port, self.b_port) < 1024 else 'high'}"
        return self.proto

    @property
    def retrans_ratio(self) -> float:
        return self.retrans / self.data_segments if self.data_segments else 0.0


Key = tuple[str, str, int, str, int]


class FlowTable:
    """Groups decoded packets into flows. A new SYN on a flow that was closed or reset starts a new one."""

    def __init__(self, max_flows: int = 1_000_000) -> None:
        self.active: dict[Key, Flow] = {}
        self.done: list[Flow] = []
        self.max_flows = max_flows
        self.dropped = 0  # packets of flows that did not fit in the table

    def all(self) -> list[Flow]:
        return [*self.done, *self.active.values()]

    def add(self, d: Decoded) -> Flow | None:
        if d.proto not in ("tcp", "udp", "icmp", "icmp6"):
            return None
        if (d.src, d.sport) <= (d.dst, d.dport):
            key: Key = (d.proto, d.src, d.sport, d.dst, d.dport)
        else:
            key = (d.proto, d.dst, d.dport, d.src, d.sport)
        flow = self.active.get(key)
        fresh_syn = d.proto == "tcp" and d.flags & SYN and not d.flags & ACK
        if flow is not None and fresh_syn and (flow.fin or flow.rst_a or flow.rst_b) and d.src == flow.a:
            self.done.append(flow)  # the same ports used again for a new connection
            del self.active[key]
            flow = None
        if flow is None:
            if len(self.active) + len(self.done) >= self.max_flows:
                self.dropped += 1
                return None
            flow = Flow(d.proto, d.src, d.sport, d.dst, d.dport, d.ts, d.ts)
            self.active[key] = flow
        side = 0 if (d.src, d.sport) == (flow.a, flow.a_port) else 1
        self._count(flow, d, side)
        return flow

    @staticmethod
    def _count(f: Flow, d: Decoded, side: int) -> None:
        f.last = max(f.last, d.ts)
        f.pkts[side] += 1
        f.bytes[side] += d.wirelen
        f.data[side] += d.payload_len
        if d.dns:
            f.names.add(d.dns.qname)
        if d.sni:
            f.names.add(d.sni)
        if d.http and d.http.host:
            f.names.add(d.http.host)
        if d.proto != "tcp":
            return
        flags = d.flags
        if flags & RST:
            if side == 0:
                f.rst_a = True
            else:
                f.rst_b = True
        if flags & FIN:
            f.fin += 1
        if flags & SYN:
            if not flags & ACK and side == 0:
                f.syn += 1
                if f.syn == 1:
                    f.syn_ts = d.ts
                else:
                    f.retrans += 1  # the SYN was sent again
            elif flags & ACK and side == 1 and f.syn and not f.synack:
                f.synack = True
                f.rtt = max(0.0, d.ts - f.syn_ts)
        elif flags & ACK and side == 0 and f.synack and not f.acked:
            f.acked = True
        if d.payload_len:
            f.data_segments += 1
            end = (d.seq + d.payload_len) & _MASK
            hi = f.hi_seq[side]
            if hi is None:
                f.hi_seq[side] = end
            else:
                delta = (end - hi) & _MASK
                if delta == 0 or delta >= 0x80000000:
                    f.retrans += 1
                else:
                    f.hi_seq[side] = end
