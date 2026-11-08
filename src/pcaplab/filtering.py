"""A small filter language, close to what tcpdump and Wireshark users type:

    tcp and port 443        host 10.0.0.5 and not dns        src net 192.168.0.0/16 and (syn or rst)
    dns and name example.com        vlan 20        http        portrange 8000-8100        error

Words: tcp udp icmp icmp6 arp ip ip6 eth dns http tls | host/src/dst [host] ADDRESS | [src|dst] net CIDR |
[src|dst] port N | portrange A-B | vlan [N] | name TEXT | syn synack rst fin | error | and or not ( )"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from functools import lru_cache

from .decode import ACK, FIN, RST, SYN, Decoded

Predicate = Callable[[Decoded], bool]
LAYERS = {"tcp", "udp", "icmp", "icmp6", "arp", "ip", "ip6", "eth", "dns", "http", "tls"}
_TOKEN = re.compile(r"\(|\)|[^\s()]+")


class FilterError(ValueError):
    """The filter expression is not valid."""


@lru_cache(maxsize=4096)
def _addr(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


class _Parser:
    def __init__(self, text: str) -> None:
        self.tokens = _TOKEN.findall(text)
        self.pos = 0

    def peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self, what: str = "a word") -> str:
        tok = self.peek()
        if tok is None:
            raise FilterError(f"the filter ends where {what} was expected")
        self.pos += 1
        return tok

    def parse(self) -> Predicate:
        if not self.tokens:
            raise FilterError("the filter is empty")
        node = self._or()
        if self.peek() is not None:
            raise FilterError(f"unexpected {self.peek()!r}")
        return node

    def _or(self) -> Predicate:
        parts = [self._and()]
        while (self.peek() or "").lower() == "or":
            self.pos += 1
            parts.append(self._and())
        return parts[0] if len(parts) == 1 else (lambda d: any(p(d) for p in parts))

    def _and(self) -> Predicate:
        parts = [self._not()]
        while (self.peek() or "").lower() == "and":
            self.pos += 1
            parts.append(self._not())
        return parts[0] if len(parts) == 1 else (lambda d: all(p(d) for p in parts))

    def _not(self) -> Predicate:
        if (self.peek() or "").lower() == "not":
            self.pos += 1
            inner = self._not()
            return lambda d: not inner(d)
        return self._atom()

    def _atom(self) -> Predicate:
        tok = self.take()
        low = tok.lower()
        if tok == "(":
            node = self._or()
            if self.take("')'") != ")":
                raise FilterError("missing ')'")
            return node
        if tok == ")" or low in ("and", "or"):
            raise FilterError(f"unexpected {tok!r}")
        if low in LAYERS:
            return lambda d: low in d.layers
        if low in ("syn", "synack", "rst", "fin"):
            return _flag(low)
        if low == "error":
            return lambda d: bool(d.error)
        if low == "vlan":
            nxt = self.peek()
            if nxt is not None and nxt.isdigit():
                self.pos += 1
                vid = int(nxt)
                return lambda d: d.vlan == vid
            return lambda d: d.vlan is not None
        if low == "name":
            text = self.take("a name").lower()
            return lambda d: _has_name(d, text)
        if low == "portrange":
            return self._ports("any", self.take("a port range"), True)
        direction = "any"
        if low in ("src", "dst"):
            direction = low
            tok = self.take("an address, host, net or port")
            low = tok.lower()
        if low == "host":
            return self._host(direction, self.take("an address"))
        if low == "net":
            return self._net(direction, self.take("a network"))
        if low == "port":
            return self._ports(direction, self.take("a port number"), False)
        if _addr(tok) is not None:  # a bare address means "host ADDRESS"
            return self._host(direction, tok)
        raise FilterError(f"unknown word {tok!r}")

    @staticmethod
    def _host(direction: str, text: str) -> Predicate:
        addr = _addr(text)
        if addr is None:
            raise FilterError(f"{text!r} is not an IP address")
        value = addr.compressed
        if direction == "src":
            return lambda d: d.src == value
        if direction == "dst":
            return lambda d: d.dst == value
        return lambda d: d.src == value or d.dst == value

    @staticmethod
    def _net(direction: str, text: str) -> Predicate:
        try:
            net = ipaddress.ip_network(text, strict=False)
        except ValueError as exc:
            raise FilterError(f"{text!r} is not a network such as 10.0.0.0/8") from exc

        def inside(ip: str) -> bool:
            a = _addr(ip)
            return a is not None and a.version == net.version and a in net

        if direction == "src":
            return lambda d: inside(d.src)
        if direction == "dst":
            return lambda d: inside(d.dst)
        return lambda d: inside(d.src) or inside(d.dst)

    @staticmethod
    def _ports(direction: str, text: str, is_range: bool) -> Predicate:
        try:
            lo, hi = (int(x) for x in text.split("-", 1)) if is_range else (int(text), int(text))
        except ValueError as exc:
            raise FilterError(f"{text!r} is not a port{' range such as 8000-8100' if is_range else ''}") from exc
        if not 0 <= lo <= hi <= 65535:
            raise FilterError(f"{text!r} is outside 0-65535")

        def has(d: Decoded, port: int) -> bool:
            return d.proto in ("tcp", "udp") and lo <= port <= hi

        if direction == "src":
            return lambda d: has(d, d.sport)
        if direction == "dst":
            return lambda d: has(d, d.dport)
        return lambda d: has(d, d.sport) or has(d, d.dport)


def _flag(name: str) -> Predicate:
    def test(d: Decoded) -> bool:
        if d.proto != "tcp":
            return False
        if name == "syn":
            return bool(d.flags & SYN) and not d.flags & ACK
        if name == "synack":
            return bool(d.flags & SYN) and bool(d.flags & ACK)
        return bool(d.flags & (RST if name == "rst" else FIN))

    return test


def _has_name(d: Decoded, text: str) -> bool:
    names = []
    if d.dns:
        names.append(d.dns.qname)
    if d.sni:
        names.append(d.sni)
    if d.http and d.http.host:
        names.append(d.http.host)
    return any(n == text or n.endswith("." + text) for n in names)


def compile_filter(text: str) -> Predicate:
    return _Parser(text).parse()
