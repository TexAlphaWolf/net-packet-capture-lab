"""Packet decoding: Ethernet (with VLAN tags), Linux cooked and raw IP, ARP, IPv4, IPv6, TCP, UDP, ICMP, and above
them DNS, HTTP/1.x requests and responses, and the server name of a TLS ClientHello.

``decode`` never raises: a packet that cannot be read comes back with ``error`` set and as much as was understood."""

from __future__ import annotations

import base64
import binascii
import re
import socket
import struct
from dataclasses import dataclass, field

from .model import (
    LINK_ETHERNET,
    LINK_IPV4,
    LINK_IPV6,
    LINK_LINUX_SLL,
    LINK_LINUX_SLL2,
    LINK_LOOP,
    LINK_NULL,
    LINK_RAW,
    Packet,
)

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10
DNS_PORTS = (53, 5353)
DNS_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    41: "OPT",
    43: "DS",
    46: "RRSIG",
    48: "DNSKEY",
    65: "HTTPS",
    255: "ANY",
}
DNS_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE ")
_REQUEST = re.compile(rb"^([A-Z]+) (\S{1,2048}) HTTP/1\.[01]\r\n")
_RESPONSE = re.compile(rb"^HTTP/1\.[01] (\d{3})[ \r]")
_UNSAFE = re.compile(r"[^\x21-\x7e]")


def clean(text: str, limit: int = 255) -> str:
    """Text that came from the network, safe to print: no spaces, controls or non-ASCII."""
    return _UNSAFE.sub("?", text)[:limit]


@dataclass(slots=True)
class Arp:
    op: int  # 1 request, 2 reply
    sha: str
    spa: str
    tha: str
    tpa: str


@dataclass(slots=True)
class Dns:
    id: int
    response: bool
    rcode: int
    qname: str  # lower case, without the final dot
    qtype: int
    answers: list[tuple[str, int, str]] = field(default_factory=list)  # (name, type, text)

    @property
    def qtype_name(self) -> str:
        return DNS_TYPES.get(self.qtype, f"TYPE{self.qtype}")

    @property
    def rcode_name(self) -> str:
        return DNS_RCODES.get(self.rcode, f"RCODE{self.rcode}")


@dataclass(slots=True)
class Http:
    is_request: bool
    method: str = ""
    target: str = ""  # path only: the query string is dropped, it often carries tokens
    status: int = 0
    host: str = ""
    auth_scheme: str = ""  # "basic", "bearer", ...
    auth_user: str = ""  # only for Basic; the password is never kept


@dataclass(slots=True)
class Decoded:
    index: int
    ts: float
    wirelen: int
    caplen: int
    eth_src: str = ""
    eth_dst: str = ""
    vlan: int | None = None
    arp: Arp | None = None
    ip_version: int = 0
    src: str = ""
    dst: str = ""
    ttl: int = 0
    fragment: bool = False  # not the first fragment: no transport header here
    proto: str = ""  # "tcp", "udp", "icmp", "icmp6", "arp", "other" (an IP protocol), "" (not IP)
    ip_proto: int = 0
    sport: int = 0
    dport: int = 0
    flags: int = 0
    seq: int = 0
    ack: int = 0
    win: int = 0
    icmp_type: int = -1
    icmp_code: int = 0
    payload_len: int = 0  # as it was on the wire, even if the capture cut it
    payload: bytes = b""
    dns: Dns | None = None
    http: Http | None = None
    sni: str = ""
    error: str = ""

    @property
    def is_ip(self) -> bool:
        return self.ip_version != 0

    @property
    def layers(self) -> frozenset[str]:
        """The names the filter and the protocol counts use."""
        out = set()
        if self.eth_src:
            out.add("eth")
        if self.vlan is not None:
            out.add("vlan")
        if self.arp:
            out.add("arp")
        if self.ip_version == 4:
            out.add("ip")
        elif self.ip_version == 6:
            out.add("ip6")
        if self.proto in ("tcp", "udp", "icmp", "icmp6"):
            out.add(self.proto)
        if self.dns:
            out.add("dns")
        if self.http:
            out.add("http")
        if self.sni:
            out.add("tls")
        return frozenset(out)


class _Bad(Exception):
    pass


def _mac(b: bytes) -> str:
    return b.hex(":")


def _ip4(b: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET, b)


def _ip6(b: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET6, b)


def decode(pkt: Packet) -> Decoded:
    d = Decoded(pkt.index, pkt.ts, pkt.wirelen, len(pkt.data))
    try:
        _link(d, pkt.linktype, pkt.data)
    except (_Bad, struct.error, IndexError, ValueError) as exc:
        d.error = str(exc) if isinstance(exc, _Bad) else "malformed packet"
    return d


def _link(d: Decoded, linktype: int, data: bytes) -> None:
    if linktype == LINK_ETHERNET:
        if len(data) < 14:
            raise _Bad("truncated Ethernet header")
        d.eth_dst, d.eth_src = _mac(data[0:6]), _mac(data[6:12])
        etype = struct.unpack_from("!H", data, 12)[0]
        pos = 14
        for _ in range(2):  # at most two tags (802.1Q, 802.1ad)
            if etype not in (0x8100, 0x88A8):
                break
            if len(data) < pos + 4:
                raise _Bad("truncated VLAN tag")
            tci, etype = struct.unpack_from("!HH", data, pos)
            if d.vlan is None:
                d.vlan = tci & 0x0FFF
            pos += 4
        _network(d, etype, data[pos:])
    elif linktype == LINK_LINUX_SLL:
        if len(data) < 16:
            raise _Bad("truncated Linux cooked header")
        halen = struct.unpack_from("!H", data, 4)[0]
        if halen == 6:
            d.eth_src = _mac(data[6:12])
        _network(d, struct.unpack_from("!H", data, 14)[0], data[16:])
    elif linktype == LINK_LINUX_SLL2:
        if len(data) < 20:
            raise _Bad("truncated Linux cooked header")
        if data[11] == 6:
            d.eth_src = _mac(data[12:18])
        _network(d, struct.unpack_from("!H", data, 0)[0], data[20:])
    elif linktype in (LINK_NULL, LINK_LOOP):
        if len(data) < 5:
            raise _Bad("truncated loopback header")
        _ip_by_version(d, data[4:])
    elif linktype in (LINK_RAW, LINK_IPV4, LINK_IPV6):
        _ip_by_version(d, data)
    else:
        raise _Bad(f"unsupported link type {linktype}")


def _ip_by_version(d: Decoded, data: bytes) -> None:
    if not data:
        raise _Bad("empty packet")
    version = data[0] >> 4
    if version not in (4, 6):
        raise _Bad("not an IP packet")
    _network(d, 0x0800 if version == 4 else 0x86DD, data)


def _network(d: Decoded, etype: int, data: bytes) -> None:
    if etype == 0x0800:
        _ipv4(d, data)
    elif etype == 0x86DD:
        _ipv6(d, data)
    elif etype == 0x0806:
        _arp(d, data)


def _arp(d: Decoded, data: bytes) -> None:
    if len(data) < 28:
        raise _Bad("truncated ARP packet")
    _htype, ptype, hlen, plen, op = struct.unpack_from("!HHBBH", data, 0)
    if hlen != 6 or plen != 4 or ptype != 0x0800:
        return
    d.arp = Arp(op, _mac(data[8:14]), _ip4(data[14:18]), _mac(data[18:24]), _ip4(data[24:28]))
    d.proto = "arp"


def _ipv4(d: Decoded, data: bytes) -> None:
    if len(data) < 20:
        raise _Bad("truncated IPv4 header")
    ihl = (data[0] & 0x0F) * 4
    total, _ident, frag = struct.unpack_from("!HHH", data, 2)
    if data[0] >> 4 != 4 or ihl < 20 or total < ihl:
        raise _Bad("bad IPv4 header")
    d.ip_version, d.ttl, d.ip_proto = 4, data[8], data[9]
    d.src, d.dst = _ip4(data[12:16]), _ip4(data[16:20])
    # the length in the header cuts off the padding Ethernet adds to short frames
    body = data[ihl:total]
    if frag & 0x1FFF:
        d.fragment, d.proto = True, "other"
        return
    _transport(d, d.ip_proto, body, total - ihl)


def _ipv6(d: Decoded, data: bytes) -> None:
    if len(data) < 40:
        raise _Bad("truncated IPv6 header")
    plen, nxt, hop = struct.unpack_from("!HBB", data, 4)
    if data[0] >> 4 != 6:
        raise _Bad("bad IPv6 header")
    d.ip_version, d.ttl = 6, hop
    d.src, d.dst = _ip6(data[8:24]), _ip6(data[24:40])
    pos, end = 40, 40 + plen
    for _ in range(8):  # extension headers
        if nxt in (0, 43, 60):
            if len(data) < pos + 8:
                raise _Bad("truncated IPv6 extension header")
            nxt, size = data[pos], (data[pos + 1] + 1) * 8
        elif nxt == 51:
            if len(data) < pos + 8:
                raise _Bad("truncated IPv6 extension header")
            nxt, size = data[pos], (data[pos + 1] + 2) * 4
        elif nxt == 44:
            if len(data) < pos + 8:
                raise _Bad("truncated IPv6 fragment header")
            if struct.unpack_from("!H", data, pos + 2)[0] & 0xFFF8:
                d.ip_proto, d.fragment, d.proto = data[pos], True, "other"
                return
            nxt, size = data[pos], 8
        else:
            break
        pos += size
    d.ip_proto = nxt
    _transport(d, nxt, data[pos:end], max(0, end - pos))


def _transport(d: Decoded, proto: int, body: bytes, wire_len: int) -> None:
    if proto == 6:
        _tcp(d, body, wire_len)
    elif proto == 17:
        _udp(d, body, wire_len)
    elif (proto == 1 and d.ip_version == 4) or (proto == 58 and d.ip_version == 6):
        d.proto = "icmp" if proto == 1 else "icmp6"
        if len(body) < 4:
            raise _Bad("truncated ICMP header")
        d.icmp_type, d.icmp_code = body[0], body[1]
    else:
        d.proto = "other"


def _tcp(d: Decoded, body: bytes, wire_len: int) -> None:
    d.proto = "tcp"
    if len(body) < 20:
        raise _Bad("truncated TCP header")
    d.sport, d.dport, d.seq, d.ack, off, d.flags, d.win = struct.unpack_from("!HHIIBBH", body, 0)
    hlen = (off >> 4) * 4
    d.flags &= 0x3F
    if hlen < 20:
        raise _Bad("bad TCP header length")
    d.payload = body[hlen:]
    d.payload_len = max(0, wire_len - hlen)
    if d.payload:
        _tcp_app(d)


def _udp(d: Decoded, body: bytes, wire_len: int) -> None:
    d.proto = "udp"
    if len(body) < 8:
        raise _Bad("truncated UDP header")
    d.sport, d.dport, length = struct.unpack_from("!HHH", body, 0)
    d.payload = body[8 : length if length >= 8 else None]
    d.payload_len = max(0, wire_len - 8)
    if d.sport in DNS_PORTS or d.dport in DNS_PORTS:
        d.dns = parse_dns(d.payload)


def _tcp_app(d: Decoded) -> None:
    p = d.payload
    if d.sport in DNS_PORTS or d.dport in DNS_PORTS:
        if len(p) > 2 and struct.unpack_from("!H", p, 0)[0] == len(p) - 2:
            d.dns = parse_dns(p[2:])
        return
    if p[0] == 0x16:
        d.sni = parse_sni(p)
    elif p.startswith(HTTP_METHODS) or p.startswith(b"HTTP/1."):
        d.http = parse_http(p)


# DNS ---------------------------------------------------------------------------------------------------------


def _dns_name(buf: bytes, pos: int) -> tuple[str, int]:
    labels: list[str] = []
    end = -1
    hops = 0
    size = 0
    while True:
        if pos >= len(buf):
            raise _Bad("truncated DNS name")
        n = buf[pos]
        if n == 0:
            pos += 1
            break
        if n & 0xC0 == 0xC0:
            if pos + 1 >= len(buf):
                raise _Bad("truncated DNS name")
            if end < 0:
                end = pos + 2
            hops += 1
            pos = ((n & 0x3F) << 8) | buf[pos + 1]
            if hops > 32 or pos >= len(buf):
                raise _Bad("bad DNS compression pointer")
            continue
        if n & 0xC0:
            raise _Bad("bad DNS label")
        pos += 1
        size += n + 1
        if pos + n > len(buf) or size > 255:
            raise _Bad("bad DNS name")
        labels.append(clean(buf[pos : pos + n].decode("latin-1")).lower())
        pos += n
    return ".".join(labels), (end if end >= 0 else pos)


def _rdata(buf: bytes, pos: int, rtype: int, rdlen: int) -> str:
    raw = buf[pos : pos + rdlen]
    if rtype == 1 and rdlen == 4:
        return _ip4(raw)
    if rtype == 28 and rdlen == 16:
        return _ip6(raw)
    if rtype in (2, 5, 12):
        return _dns_name(buf, pos)[0]
    if rtype == 15 and rdlen > 2:
        return f"{struct.unpack_from('!H', raw)[0]} {_dns_name(buf, pos + 2)[0]}"
    if rtype == 16:
        parts, i = [], 0
        while i < len(raw):
            n = raw[i]
            parts.append(clean(raw[i + 1 : i + 1 + n].decode("latin-1"), 60))
            i += 1 + n
        return " ".join(parts)[:80]
    return f"<{rdlen} bytes>"


def parse_dns(buf: bytes) -> Dns | None:
    """The first question and the answers of a DNS message, or None if the bytes are not DNS."""
    if len(buf) < 12:
        return None
    ident, flags, qd, an = struct.unpack_from("!HHHH", buf, 0)
    if qd != 1 or (flags >> 11) & 0xF > 5:  # one question; opcodes above 5 are not in use
        return None
    try:
        qname, pos = _dns_name(buf, 12)
        if pos + 4 > len(buf):
            return None  # the question is cut
        qtype = struct.unpack_from("!H", buf, pos)[0]
    except (_Bad, struct.error):
        return None
    msg = Dns(ident, bool(flags & 0x8000), flags & 0xF, qname, qtype)
    pos += 4
    try:
        for _ in range(min(an, 50)):
            name, pos = _dns_name(buf, pos)
            rtype, _cls, _ttl, rdlen = struct.unpack_from("!HHIH", buf, pos)
            pos += 10
            if pos + rdlen > len(buf):
                break
            msg.answers.append((name, rtype, _rdata(buf, pos, rtype, rdlen)))
            pos += rdlen
    except (_Bad, struct.error):
        pass  # a damaged answer section: keep the question and the answers read so far
    return msg


# HTTP ---------------------------------------------------------------------------------------------------------


def parse_http(p: bytes) -> Http | None:
    head = p[:8192].split(b"\r\n\r\n", 1)[0]
    req = _REQUEST.match(head + b"\r\n")
    res = _RESPONSE.match(head)
    if req:
        out = Http(
            True, method=req.group(1).decode(), target=clean(req.group(2).decode("latin-1").split("?", 1)[0], 120)
        )
    elif res:
        out = Http(False, status=int(res.group(1)))
    else:
        return None
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        key = name.strip().lower()
        value = value.strip()
        if key == b"host":
            out.host = clean(value.decode("latin-1").lower(), 100)
        elif key in (b"authorization", b"proxy-authorization") and not out.auth_scheme:
            scheme, _, token = value.partition(b" ")
            out.auth_scheme = clean(scheme.decode("latin-1").lower(), 16)
            if out.auth_scheme == "basic":
                try:
                    user = base64.b64decode(token.strip(), validate=True).split(b":", 1)[0]
                except (binascii.Error, ValueError):
                    user = b""
                out.auth_user = clean(user.decode("latin-1"), 64)
    return out


# TLS ----------------------------------------------------------------------------------------------------------


def parse_sni(p: bytes) -> str:
    """The server_name of a TLS ClientHello, or "" for any other TLS record."""
    # record: type 22, version, length; handshake: type 1, 3-byte length; version, random, session id ...
    if len(p) < 48 or p[0] != 0x16 or p[1] != 3 or p[5] != 1:
        return ""
    try:
        pos = 5 + 4 + 2 + 32
        pos += 1 + p[pos]  # session id
        pos += 2 + struct.unpack_from("!H", p, pos)[0]  # cipher suites
        pos += 1 + p[pos]  # compression
        end = min(len(p), pos + 2 + struct.unpack_from("!H", p, pos)[0])
        pos += 2
        while pos + 4 <= end:
            etype, elen = struct.unpack_from("!HH", p, pos)
            pos += 4
            if etype == 0 and elen >= 5:  # server_name
                nlen = struct.unpack_from("!H", p, pos + 3)[0]
                return clean(p[pos + 5 : pos + 5 + nlen].decode("latin-1").lower(), 255)
            pos += elen
    except (struct.error, IndexError):
        return ""
    return ""
