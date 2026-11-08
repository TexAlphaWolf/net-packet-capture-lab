from __future__ import annotations

from conftest import analyze_frames
from pcaplab.analyze import MAX_NAMES, Result, entropy, registered_domain
from pcaplab.filtering import compile_filter
from pcaplab.synth import GATEWAY, GW_MAC, LAN, Traffic, arp, ether, mac_of


def test_registered_domain() -> None:
    assert registered_domain("example.com") == "example.com"
    assert registered_domain("a.b.example.com") == "example.com"
    assert registered_domain("www.example.co.uk") == "example.co.uk"
    assert registered_domain("localhost") == "localhost"
    assert (
        registered_domain("x.y.com.au") == "y.com.au" or registered_domain("x.y.com.au") == "com.au"
    )  # near the limit of the rule


def test_entropy() -> None:
    assert entropy("") == 0.0
    assert entropy("aaaa") == 0.0
    assert abs(entropy("abcd") - 2.0) < 1e-9


def test_scenario_counts(scenario_result: Result) -> None:
    r = scenario_result
    assert r.packets == sum(r.kinds.values()) > 10_000
    assert r.bytes >= r.packets * 60
    assert r.first < r.last and r.duration == r.last - r.first
    assert sum(v[0] for v in r.timeline.values()) == r.packets
    assert r.apps["dns"] > 1000 and r.apps["tls"] > 100
    assert r.dns_rcodes["NXDOMAIN"] >= 60 and r.dns_rcodes["NOERROR"] > 500
    assert "www.example.com" in r.dns_queries and "www.example.com" in r.sni
    assert not r.errors


def test_hosts_sum_to_traffic(scenario_result: Result) -> None:
    r = scenario_result
    sent = sum(h[1] for h in r.hosts.values())
    got = sum(h[3] for h in r.hosts.values())
    assert sent == got  # every IP packet has a sender and a receiver


def test_dns_aggregation() -> None:
    tr = Traffic(1)
    for i in range(30):
        tr.dns_lookup(100.0 + i, f"{LAN}9", f"host{i}.sub.example.org")
    tr.dns_lookup(200.0, f"{LAN}9", "example.org")
    r = analyze_frames(tr.frames)
    agg = r.dns_agg[(f"{LAN}9", "example.org")]
    assert agg.queries == 31 and agg.unique == 30 and agg.txt_queries == 0
    assert abs(agg.mean_len - (10 * 9 + 20 * 10) / 30) < 1e-9 and 2.0 < agg.mean_entropy < 4.0
    assert agg.first == 100.0 and agg.last == 200.0


def test_name_limits() -> None:
    tr = Traffic(1)
    for i in range(MAX_NAMES + 50):
        tr.dns_lookup(100.0 + i * 0.001, f"{LAN}9", f"n{i}.example.org", rcode=3)
    r = analyze_frames(tr.frames)
    assert r.dns_agg[(f"{LAN}9", "example.org")].unique == MAX_NAMES
    assert len(r.nx[f"{LAN}9"].names) == MAX_NAMES and r.nx[f"{LAN}9"].responses == MAX_NAMES + 50


def test_arp_tracking() -> None:
    tr = Traffic(1)
    who = f"{LAN}12"
    evil = mac_of(f"{LAN}66")

    def reply(t: float, mac: bytes, src_mac: bytes) -> None:
        tr.frames.append((t, ether(mac_of(who), src_mac, 0x0806, arp(2, mac, GATEWAY, mac_of(who), who))))

    reply(1.0, GW_MAC, GW_MAC)
    reply(2.0, GW_MAC, GW_MAC)  # the same owner again: no change
    reply(3.0, evil, evil)
    reply(4.0, GW_MAC, evil)  # announced MAC differs from the Ethernet source
    probe = ether(b"\xff" * 6, evil, 0x0806, arp(1, evil, "0.0.0.0", b"\x00" * 6, "10.0.0.50"))
    tr.frames.append((5.0, probe))
    r = analyze_frames(tr.frames)
    assert [c.mac for c in r.arp[GATEWAY]] == ["02:00:0a:00:00:01", "02:00:0a:00:00:42", "02:00:0a:00:00:01"]
    assert "0.0.0.0" not in r.arp  # a probe does not claim an address
    assert len(r.arp_mismatch) == 1 and r.arp_mismatch[0][1] == GATEWAY


def test_credentials_without_the_secret() -> None:
    tr = Traffic(1)
    tr.http_basic(10.0, f"{LAN}12", f"{LAN}8", 8080, "admin", "S3cret!pw")
    tr.http_basic(20.0, f"{LAN}12", f"{LAN}8", 8080, "admin", "S3cret!pw")  # the same login twice: reported once
    tr.http_basic(30.0, f"{LAN}12", f"{LAN}8", 8080, "bob", "other")
    tr.ftp_login(40.0, f"{LAN}14", f"{LAN}9", "backup", "hunter2")
    r = analyze_frames(tr.frames)
    assert [(c.kind, c.user) for c in r.creds] == [("http-basic", "admin"), ("http-basic", "bob"), ("ftp", "")]
    assert "S3cret" not in repr(r.creds) and "hunter2" not in repr(r.creds)


def test_filter_keeps_only_matching_packets(scenario: tuple[list, list]) -> None:
    r = analyze_frames(scenario[0], keep=compile_filter("dns"))
    assert r.packets > 1000 and set(r.kinds) == {"udp"} and r.apps["dns"] == r.packets


def test_empty_result() -> None:
    r = analyze_frames([])
    assert r.packets == 0 and r.duration == 0.0 and r.flows == []
