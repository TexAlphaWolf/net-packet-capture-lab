from __future__ import annotations

import random
import struct

from fixtures import PACKETS
from pcaplab.decode import ACK, SYN, Decoded, decode, parse_dns, parse_http, parse_sni
from pcaplab.model import Packet
from pcaplab.synth import dns_message, ipv4, ipv6, tcp, tls_client_hello, udp


def dec(data: bytes, linktype: int = 1) -> Decoded:
    return decode(Packet(1, 1_760_000_000.0, len(data), linktype, data))


def test_tcp_syn() -> None:
    d = dec(PACKETS["tcp_syn"])
    assert (d.eth_src, d.eth_dst) == ("aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02")
    assert (d.proto, d.ip_version, d.src, d.dst, d.ttl) == ("tcp", 4, "10.1.2.3", "192.0.2.9", 60)
    assert (d.sport, d.dport, d.seq, d.ack) == (40000, 443, 1000, 0)
    assert d.flags == SYN and d.payload_len == 0 and not d.error
    assert d.layers == {"eth", "ip", "tcp"}


def test_dns_query_and_response() -> None:
    q = dec(PACKETS["dns_q"])
    assert q.dns and not q.dns.response
    assert (q.dns.id, q.dns.qname, q.dns.qtype_name) == (0x1234, "www.example.com", "A")  # the name is lower-cased
    assert (q.sport, q.dport) == (5354, 53) and "dns" in q.layers
    r = dec(PACKETS["dns_r"])
    assert r.dns and r.dns.response and r.dns.rcode_name == "NOERROR"
    assert r.dns.answers == [("www.example.com", 1, "198.51.100.7"), ("www.example.com", 16, "hello")]


def test_vlan_ethernet_padding_and_udp() -> None:
    d = dec(PACKETS["vlan_udp"])
    assert d.vlan == 20 and "vlan" in d.layers
    assert d.proto == "udp" and (d.sport, d.dport) == (1000, 2000)
    assert d.payload == b"hi" and d.payload_len == 2  # the Ethernet padding is not payload


def test_ipv6_tcp() -> None:
    d = dec(PACKETS["v6_tcp"])
    assert (d.ip_version, d.src, d.dst, d.ttl) == (6, "2001:db8::1", "2001:db8::2", 55)
    assert d.proto == "tcp" and d.flags == SYN | ACK and (d.seq, d.ack) == (5, 6) and "ip6" in d.layers


def test_icmp_and_arp() -> None:
    d = dec(PACKETS["icmp"])
    assert d.proto == "icmp" and (d.icmp_type, d.icmp_code) == (8, 0)
    a = dec(PACKETS["arp"])
    assert a.proto == "arp" and a.arp is not None and not a.is_ip
    assert (a.arp.op, a.arp.sha, a.arp.spa, a.arp.tpa) == (1, "aa:bb:cc:00:00:01", "10.1.2.3", "10.1.2.1")


def test_http_request_keeps_no_secret() -> None:
    d = dec(PACKETS["http_get"])
    h = d.http
    assert h is not None and h.is_request
    assert (h.method, h.target, h.host) == ("GET", "/a/b", "files.example.com")  # the query string is dropped
    assert (h.auth_scheme, h.auth_user) == ("basic", "alice")
    assert "password" not in repr(h) and "SECRET" not in repr(h)
    r = dec(PACKETS["http_resp"]).http
    assert r is not None and not r.is_request and r.status == 404


def test_fragment_has_no_transport() -> None:
    d = dec(PACKETS["ip_fragment"])
    assert d.fragment and d.proto == "other" and d.sport == 0


def test_other_link_types() -> None:
    ip = ipv4("10.0.0.1", "10.0.0.2", 6, tcp("10.0.0.1", "10.0.0.2", 1, 2, 0, 0, SYN))
    assert dec(ip, 101).dport == 2 and dec(ip, 228).proto == "tcp"
    ip6 = ipv6("2001:db8::1", "2001:db8::2", 6, tcp("2001:db8::1", "2001:db8::2", 1, 2, 0, 0, SYN))
    assert dec(ip6, 229).ip_version == 6 and dec(ip6, 101).proto == "tcp"
    sll = struct.pack("!HHH8sH", 0, 1, 6, b"\xaa\xbb\xcc\x00\x00\x09\x00\x00", 0x0800) + ip
    d = dec(sll, 113)
    assert d.eth_src == "aa:bb:cc:00:00:09" and d.proto == "tcp"
    for lt in (0, 108):  # loopback captures: four bytes of address family before the IP packet
        assert dec(b"\x02\x00\x00\x00" + ip, lt).dport == 2
        assert dec(b"\x00\x00\x00\x1e" + ip6, lt).ip_version == 6
    sll2 = struct.pack("!HHIHBB8s", 0x0800, 0, 3, 1, 0, 6, b"\xaa\xbb\xcc\x00\x00\x0a\x00\x00") + ip
    d = dec(sll2, 276)
    assert d.eth_src == "aa:bb:cc:00:00:0a" and d.proto == "tcp" and d.dport == 2
    assert dec(sll2[:10], 276).error == "truncated Linux cooked header"
    assert dec(b"\x02\x00\x00", 0).error == "truncated loopback header"
    assert dec(b"\x20" + b"\x00" * 30, 101).error == "not an IP packet"
    assert dec(b"", 101).error == "empty packet"
    assert dec(b"\x00" * 30, 107).error == "unsupported link type 107"
    assert dec(b"\x00" * 8, 113).error == "truncated Linux cooked header"


def test_ipv6_extension_headers() -> None:
    seg = tcp("2001:db8::1", "2001:db8::2", 1, 2, 0, 0, SYN)
    hop = bytes([6, 0, 1, 4, 0, 0, 0, 0])  # hop-by-hop with padding, next header TCP
    d = dec(ipv6("2001:db8::1", "2001:db8::2", 0, hop + seg), 229)
    assert d.proto == "tcp" and d.dport == 2
    first = struct.pack("!BBHI", 6, 0, 0, 1)  # fragment header, offset 0: the TCP header is here
    assert dec(ipv6("2001:db8::1", "2001:db8::2", 44, first + seg), 229).proto == "tcp"
    later = struct.pack("!BBHI", 6, 0, 8 << 3, 1)  # offset 8: no transport header
    d = dec(ipv6("2001:db8::1", "2001:db8::2", 44, later + b"x" * 20), 229)
    assert d.fragment and d.proto == "other"
    ah = bytes([6, 1]) + b"\x00" * 10  # authentication header: (1 + 2) * 4 = 12 bytes
    assert dec(ipv6("2001:db8::1", "2001:db8::2", 51, ah + seg), 229).proto == "tcp"


def test_truncated_headers_are_reported() -> None:
    f = PACKETS["tcp_syn"]
    assert dec(f[:10]).error == "truncated Ethernet header"
    assert dec(f[:20]).error == "truncated IPv4 header"
    assert dec(f[:40]).error == "truncated TCP header"
    assert dec(PACKETS["dns_q"][:40]).error == "truncated UDP header"
    assert dec(PACKETS["icmp"][:36]).error == "truncated ICMP header"
    assert dec(PACKETS["arp"][:30]).error == "truncated ARP packet"
    assert dec(PACKETS["v6_tcp"][:30]).error == "truncated IPv6 header"
    assert dec(PACKETS["vlan_udp"][:16]).error == "truncated VLAN tag"
    # a bad header length
    bad = bytearray(f)
    bad[14] = 0x41
    assert dec(bytes(bad)).error == "bad IPv4 header"
    bad = bytearray(f)
    bad[14 + 20 + 12] = 0x10  # TCP data offset 1
    assert dec(bytes(bad)).error == "bad TCP header length"


def test_capture_cut_short_keeps_the_wire_length() -> None:
    f = PACKETS["http_get"][:60]  # the capture stops inside the TCP header's payload
    d = dec(f)
    assert d.proto == "tcp" and d.payload_len == 0x8E - 20 - 20 and d.http is None


def test_nothing_ever_raises() -> None:
    rng = random.Random(7)
    for frame in PACKETS.values():
        for n in range(len(frame) + 1):  # every prefix
            for lt in (0, 1, 101, 108, 113, 228, 229, 276):
                dec(frame[:n], lt)
        for _ in range(200):  # random damage
            bad = bytearray(frame)
            for _ in range(rng.randint(1, 6)):
                bad[rng.randrange(len(bad))] = rng.randrange(256)
            dec(bytes(bad))
    for _ in range(2000):
        dec(rng.randbytes(rng.randint(0, 120)), rng.choice([0, 1, 101, 108, 113, 228, 229, 276]))


# DNS ----------------------------------------------------------------------------------------------------------


def test_dns_record_types() -> None:
    def rr(rtype: int, rdata: bytes) -> bytes:
        return dns_message(1, "a.example", 1, response=True, answers=[(rtype, rdata)])

    cname = b"\x03www\xc0\x0e"  # www + pointer to "example" at offset 14 ("a.example": a=13.., example=14)
    m = parse_dns(rr(5, cname))
    assert m and m.answers[0][2] == "www.example"
    m = parse_dns(rr(28, bytes(15) + b"\x01"))
    assert m and m.answers[0][2] == "::1"
    m = parse_dns(rr(15, struct.pack("!H", 10) + b"\x04mail\xc0\x0e"))
    assert m and m.answers[0][2] == "10 mail.example"
    m = parse_dns(rr(99, b"\x01\x02"))
    assert m and m.answers[0][2] == "<2 bytes>"
    m = parse_dns(rr(16, b"\x03abc\x02de"))
    assert m and m.answers[0][2] == "abc de" and m.qtype_name == "A"
    assert parse_dns(dns_message(1, "x.example", 4242)).qtype_name == "TYPE4242"  # type: ignore[union-attr]
    nx = parse_dns(dns_message(1, "x.example", 1, response=True, rcode=3))
    assert nx and nx.rcode_name == "NXDOMAIN"
    assert parse_dns(dns_message(1, "x.example", 1, response=True, rcode=9)).rcode_name == "RCODE9"  # type: ignore[union-attr]


def test_dns_damage() -> None:
    assert parse_dns(b"\x00" * 5) is None
    assert parse_dns(struct.pack("!HHHHHH", 1, 0, 2, 0, 0, 0) + b"\x00\x00\x01\x00\x01") is None  # two questions
    assert parse_dns(struct.pack("!HHHHHH", 1, 0x7800, 1, 0, 0, 0) + b"\x01a\x00\x00\x01\x00\x01") is None  # opcode 15
    loop = struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0) + b"\xc0\x0c"
    assert parse_dns(loop) is None  # a pointer to itself
    assert parse_dns(struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0) + b"\x80ab") is None  # label type that does not exist
    assert parse_dns(struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0) + b"\x05ab") is None  # label longer than the message
    long = b"".join(b"\x3f" + b"a" * 63 for _ in range(5)) + b"\x00"
    assert parse_dns(struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0) + long + b"\x00\x01\x00\x01") is None  # name over 255
    assert parse_dns(struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0) + b"\x01a\x00\x00\x01") is None  # question cut
    whole = dns_message(1, "x.example", 1, response=True, answers=[(1, b"\x01\x02\x03\x04")])
    half = parse_dns(whole[:-2])  # the answer is cut: the question is kept
    assert half and half.qname == "x.example" and half.answers == []
    # control characters in a name never reach the output
    odd = parse_dns(struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0) + b"\x03a\x1b[\x00\x00\x01\x00\x01")
    assert odd and "\x1b" not in odd.qname


def test_dns_over_tcp_and_mdns() -> None:
    msg = dns_message(5, "big.example", 1)
    frame = tcp("10.0.0.1", "10.0.0.2", 5000, 53, 1, 1, ACK, struct.pack("!H", len(msg)) + msg)
    d = dec(_eth(ipv4("10.0.0.1", "10.0.0.2", 6, frame)))
    assert d.dns and d.dns.qname == "big.example"
    d = dec(_eth(ipv4("10.0.0.1", "224.0.0.251", 17, udp("10.0.0.1", "224.0.0.251", 5353, 5353, msg))))
    assert d.dns and d.dns.qname == "big.example"
    bad = tcp("10.0.0.1", "10.0.0.2", 5000, 53, 1, 1, ACK, b"\x00\x05junk")
    assert dec(_eth(ipv4("10.0.0.1", "10.0.0.2", 6, bad))).dns is None


def _eth(ip: bytes) -> bytes:
    return b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02\x08\x00" + ip


# HTTP and TLS -----------------------------------------------------------------------------------------------


def test_http_odds() -> None:
    assert parse_http(b"GET / HTTP/1.1\r\nHost: A.example\r\n\r\n").host == "a.example"  # type: ignore[union-attr]
    assert parse_http(b"NOTHTTP").__class__ is type(None)
    b = parse_http(b"GET / HTTP/1.1\r\nAuthorization: Bearer abc.def\r\n\r\n")
    assert b and (b.auth_scheme, b.auth_user) == ("bearer", "")
    b = parse_http(b"GET / HTTP/1.1\r\nAuthorization: Basic !!!notbase64\r\n\r\n")
    assert b and (b.auth_scheme, b.auth_user) == ("basic", "")
    b = parse_http(b"GET /x\x1b[31m HTTP/1.1\r\nHost: h\x07.example\r\nProxy-Authorization: Basic Ym9iOnB3\r\n\r\n")
    assert b and "\x1b" not in b.target and "\x07" not in b.host and b.auth_user == "bob"


def test_tls_sni() -> None:
    hello = tls_client_hello("Secure.Example.com", random.Random(1))
    assert parse_sni(hello) == "secure.example.com"
    d = dec(_eth(ipv4("10.0.0.1", "10.0.0.2", 6, tcp("10.0.0.1", "10.0.0.2", 5000, 443, 1, 1, ACK, hello))))
    assert d.sni == "secure.example.com" and "tls" in d.layers
    assert parse_sni(b"\x16\x03\x01" + b"\x00" * 60) == ""  # a handshake that is not a ClientHello
    assert parse_sni(b"\x17\x03\x03" + b"\x00" * 60) == ""
    for n in range(len(hello)):  # any prefix: no exception
        parse_sni(hello[:n])
