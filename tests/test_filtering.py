from __future__ import annotations

import pytest

from fixtures import PACKETS
from pcaplab.decode import decode
from pcaplab.filtering import FilterError, compile_filter
from pcaplab.model import Packet

D = {name: decode(Packet(1, 0.0, len(raw), 1, raw)) for name, raw in PACKETS.items()}


def hits(expr: str) -> set[str]:
    f = compile_filter(expr)
    return {name for name, d in D.items() if f(d)}


@pytest.mark.parametrize(
    ("expr", "want"),
    [
        ("tcp", {"tcp_syn", "v6_tcp", "http_get", "http_resp"}),
        ("udp", {"dns_q", "dns_r", "vlan_udp"}),
        ("icmp", {"icmp"}),
        ("arp", {"arp"}),
        ("ip6", {"v6_tcp"}),
        ("dns", {"dns_q", "dns_r"}),
        ("http", {"http_get", "http_resp"}),
        ("vlan", {"vlan_udp"}),
        ("vlan 20", {"vlan_udp"}),
        ("vlan 21", set()),
        ("host 10.1.2.3", {"tcp_syn", "dns_q", "dns_r", "vlan_udp", "icmp", "http_get", "http_resp", "ip_fragment"}),
        ("10.1.2.3 and udp", {"dns_q", "dns_r", "vlan_udp"}),
        ("src 10.1.2.3 and dns", {"dns_q"}),
        ("dst host 10.1.2.3 and dns", {"dns_r"}),
        ("src host 2001:db8::1", {"v6_tcp"}),
        ("host 2001:0DB8:0::1", {"v6_tcp"}),
        ("net 192.0.2.0/24", {"tcp_syn", "http_get", "http_resp"}),
        ("src net 192.0.2.0/24", {"http_resp"}),
        ("dst net 2001:db8::/32", {"v6_tcp"}),
        ("port 443", {"tcp_syn"}),
        ("dst port 53", {"dns_q"}),
        ("src port 53", {"dns_r"}),
        ("portrange 1000-2000", {"vlan_udp", "v6_tcp"}),
        ("syn", {"tcp_syn"}),
        ("synack", {"v6_tcp"}),
        ("rst or fin", set()),
        ("name example.com", {"dns_q", "dns_r", "http_get"}),
        ("name files.example.com", {"http_get"}),
        ("tcp and not port 80", {"tcp_syn"}),
        ("(dns or http) and 10.1.2.3 and not udp", {"http_get", "http_resp"}),
        ("NOT UDP AND NOT TCP AND NOT ICMP", {"arp", "ip_fragment"}),
        ("error", set()),
        ("eth", set(D)),
    ],
)
def test_expressions(expr: str, want: set[str]) -> None:
    assert hits(expr) == want


def test_error_and_tls() -> None:
    bad = decode(Packet(1, 0.0, 5, 1, b"abc"))
    assert compile_filter("error")(bad) and not compile_filter("tcp")(bad)
    assert compile_filter("tls")(D["tcp_syn"]) is False


@pytest.mark.parametrize(
    "expr",
    ["", "   ", "tcp and", "and tcp", "tcp tcp", "(tcp", "tcp)", "port", "port abc", "port 70000", "portrange 5", "portrange 9-3", "host", "host nope",
     "net 10.0.0.0/99", "src", "src nonsense", "flapdoodle", "not", "name", "tcp or or udp"],
)  # fmt: skip
def test_bad_expressions(expr: str) -> None:
    with pytest.raises(FilterError):
        compile_filter(expr)
