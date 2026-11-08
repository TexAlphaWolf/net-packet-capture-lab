from __future__ import annotations

from collections.abc import Callable

import pytest

from conftest import analyze_frames
from pcaplab.analyze import Result
from pcaplab.detect import Finding, Thresholds, detect
from pcaplab.synth import GATEWAY, GW_MAC, LAN, Traffic, arp, build_scenario, ether, mac_of
from score import score

SCANNER = "203.0.113.50"


def kinds(findings: list[Finding]) -> list[str]:
    return [f.kind for f in findings]


def run(tr: Traffic, th: Thresholds | None = None) -> list[Finding]:
    return detect(analyze_frames(tr.frames), th)


# port scans ----------------------------------------------------------------------------------------------------


def scan(n_ports: int, rate: float = 20, **kw: object) -> Traffic:
    tr = Traffic(1)
    tr.syn_scan(SCANNER, [f"{LAN}5"], list(range(1, n_ports + 1)), 100.0, rate, **kw)  # type: ignore[arg-type]
    return tr


def test_scan_threshold_is_exact() -> None:
    assert kinds(run(scan(14))) == []
    found = run(scan(15))
    assert kinds(found) == ["port-scan"] and found[0].hosts == (SCANNER,)
    assert found[0].evidence["shape"] == "vertical" and found[0].evidence["targets"] == 15


def test_scan_shapes() -> None:
    tr = Traffic(1)
    tr.syn_scan(SCANNER, [f"{LAN}{n}" for n in range(20, 60)], [445], 100.0, 10)
    f = run(tr)[0]
    assert f.evidence["shape"] == "horizontal" and f.evidence["hosts"] == 40
    tr = Traffic(1)
    tr.syn_scan(SCANNER, [f"{LAN}{n}" for n in range(20, 30)], [21, 22, 23, 80], 100.0, 10)
    f = run(tr)[0]
    assert f.evidence["shape"] == "block" and f.evidence["targets"] == 40


def test_scan_reports_open_ports_and_every_way_to_scan() -> None:
    open_ = {(f"{LAN}5", 3), (f"{LAN}5", 9)}
    for mode in ("syn", "connect"):
        f = run(scan(30, open_ports=open_, mode=mode))[0]
        assert f.evidence["open"] == [f"{LAN}5:3", f"{LAN}5:9"]
    assert run(scan(30, drop=True))[0].evidence["open"] == []  # filtered: nobody answers


def test_slow_scan_is_not_seen() -> None:
    assert run(scan(40, rate=0.1)) == []  # one probe every ten seconds: 7 in a window of 60 s


def test_scan_clusters_are_separate_findings() -> None:
    tr = scan(30)
    tr.syn_scan(SCANNER, [f"{LAN}5"], list(range(100, 140)), 5000.0, 20)
    assert kinds(run(tr)) == ["port-scan", "port-scan"]


def test_allowed_scanner_and_real_conversations() -> None:
    assert run(scan(30), Thresholds(allow_hosts=frozenset({SCANNER}))) == []
    tr = Traffic(1)
    for port in range(1, 40):  # 39 full conversations with data: a client, not a scanner
        tr.tcp_session(100.0 + port, SCANNER, f"{LAN}5", port, up=[b"hello"], down=[b"world"])
    assert run(tr) == []


# DNS --------------------------------------------------------------------------------------------------------------


def tunnel(n: int, domain: str = "t.bad.example.org") -> Traffic:
    tr = Traffic(1)
    tr.dns_tunnel(f"{LAN}23", domain, 100.0, n)
    return tr


def test_dns_tunnel_threshold() -> None:
    assert run(tunnel(24)) == []
    f = run(tunnel(25))
    assert kinds(f) == ["dns-tunnel"] and f[0].severity == "high" and f[0].evidence["names"] == 25
    assert f[0].evidence["entropy"] > 4.0 and f[0].evidence["mean_length"] > 40  # type: ignore[operator]


def test_dns_tunnel_ignore_lists() -> None:
    assert run(tunnel(60), Thresholds(ignore_domains=frozenset({"example.org"}))) == []
    assert run(tunnel(60), Thresholds(allow_hosts=frozenset({f"{LAN}23"}))) == []


def test_ordinary_names_are_not_a_tunnel() -> None:
    tr = Traffic(1)
    for i in range(200):
        tr.dns_lookup(100.0 + i, f"{LAN}9", f"h{i:03d}.cdn.example.net")  # many, but short
    assert run(tr) == []
    tr = Traffic(1)
    for i in range(60):  # long but readable, so low entropy
        tr.dns_lookup(100.0 + i, f"{LAN}9", "a" * 30 + f"{i % 3}" * 5 + f"-{i:03d}.cdn.example.net")
    assert run(tr) == []


def test_nxdomain_threshold_and_ratio() -> None:
    def storm(n: int, good: int = 0) -> Traffic:
        tr = Traffic(1)
        tr.dga(f"{LAN}31", 100.0, n)
        for i in range(good):
            tr.dns_lookup(100.0 + i * 0.1, f"{LAN}31", f"ok{i}.example.com")
        return tr

    assert run(storm(19)) == []
    f = run(storm(20))
    assert kinds(f) == ["nxdomain-storm"] and f[0].evidence["nxdomain_names"] == 20
    assert run(storm(20, good=100)) == []  # 20 of 120 answers: a busy client with some typos
    assert run(storm(40), Thresholds(allow_hosts=frozenset({f"{LAN}31"}))) == []


# beacons -----------------------------------------------------------------------------------------------------------


def beacon(n: int, interval: float = 60.0, jitter: float = 0.05, port: int = 443) -> Traffic:
    tr = Traffic(1)
    tr.beacon(f"{LAN}45", "192.0.2.77", port, 100.0, interval, n, jitter)
    return tr


def test_beacon_threshold_and_numbers() -> None:
    assert run(beacon(7)) == []
    f = run(beacon(8))
    assert kinds(f) == ["beacon"] and f[0].hosts == (f"{LAN}45", "192.0.2.77")
    assert f[0].evidence["connections"] == 8 and abs(f[0].evidence["interval_s"] - 60) < 5  # type: ignore[operator]


def test_beacon_needs_regularity() -> None:
    tr = Traffic(1)
    t = 100.0
    for _ in range(20):
        tr.tcp_session(t, f"{LAN}45", "192.0.2.77", 443, up=[b"x"], down=[b"y"])
        t += tr.rng.uniform(8, 120)
    assert run(tr) == []
    assert run(beacon(20, jitter=0.5)) == []  # wide jitter
    assert run(beacon(20, interval=3.0)) == []  # faster than the minimum gap: a burst
    assert kinds(run(beacon(20, jitter=0.1))) == ["beacon"]


def test_beacon_survives_a_missed_beat() -> None:
    tr = Traffic(1)
    t = 100.0
    for i in range(24):
        if i != 10:
            tr.tcp_session(t, f"{LAN}45", "192.0.2.77", 443, up=[b"x"], down=[b"y"])
        t += 60
    assert kinds(run(tr)) == ["beacon"]


def test_beacon_ignored_ports_and_hosts() -> None:
    tr = Traffic(1)
    t = 100.0
    for _ in range(20):  # NTP-like: UDP every 64 s
        tr.udp_frame(t, f"{LAN}45", "203.0.113.123", tr.eph(), 123, b"x" * 48)
        t += 64
    assert run(tr) == []
    assert run(beacon(20), Thresholds(allow_hosts=frozenset({f"{LAN}45"}))) == []
    assert run(beacon(20, port=53)) == []


def test_udp_beacon() -> None:
    tr = Traffic(1)
    t = 100.0
    for _ in range(12):
        tr.udp_frame(t, f"{LAN}45", "192.0.2.99", tr.eph(), 9999, b"ping")
        t += 30
    f = run(tr)
    assert kinds(f) == ["beacon"] and f[0].evidence["proto"] == "udp"


def test_retries_inside_a_second_are_one_beat() -> None:
    tr = Traffic(1)
    t = 100.0
    for _ in range(10):
        tr.tcp_session(t, f"{LAN}45", "192.0.2.77", 443, up=[b"x"], down=[b"y"])
        tr.tcp_session(t + 0.4, f"{LAN}45", "192.0.2.77", 443, up=[b"x"], down=[b"y"])
        t += 60
    f = run(tr)
    assert kinds(f) == ["beacon"] and f[0].evidence["connections"] == 10


# ARP ---------------------------------------------------------------------------------------------------------------


def arp_reply(tr: Traffic, t: float, mac: bytes, ip: str = GATEWAY) -> None:
    who = f"{LAN}12"
    tr.frames.append((t, ether(mac_of(who), mac, 0x0806, arp(2, mac, ip, mac_of(who), who))))


def test_arp_owner_change_and_flip_flop() -> None:
    tr = Traffic(1)
    arp_reply(tr, 1, GW_MAC)
    arp_reply(tr, 2, mac_of("10.0.0.66"))
    f = run(tr)
    assert kinds(f) == ["arp-conflict"] and f[0].severity == "medium" and "moved" in f[0].detail
    arp_reply(tr, 3, GW_MAC)
    f = run(tr)
    assert f[0].severity == "high" and f[0].evidence["flipping"] and "back and forth" in f[0].detail
    tr = Traffic(1)
    arp_reply(tr, 1, GW_MAC)
    arp_reply(tr, 2, GW_MAC)
    assert run(tr) == []


def test_arp_many_changes_are_shortened() -> None:
    tr = Traffic(1)
    for i in range(10):
        arp_reply(tr, i, GW_MAC if i % 2 == 0 else mac_of("10.0.0.66"))
    f = run(tr)[0]
    assert "..." in f.detail and "9 changes" in f.detail


# secrets in clear ---------------------------------------------------------------------------------------------------


def test_cleartext_findings_never_contain_the_secret() -> None:
    tr = Traffic(1)
    tr.http_basic(10.0, f"{LAN}12", f"{LAN}8", 8080, "admin", "S3cret!pw")
    tr.ftp_login(40.0, f"{LAN}14", f"{LAN}9", "backup", "hunter2")
    found = run(tr)
    assert kinds(found) == ["cleartext-credentials"] * 2 and {f.severity for f in found} == {"high"}
    text = repr(found)
    assert "S3cret" not in text and "hunter2" not in text and "admin" in text


# TCP health ----------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(("loss", "expected"), [(0.0, 0), (0.02, 0), (0.3, 1)])
def test_retransmission_finding(loss: float, expected: int) -> None:
    tr = Traffic(2)
    tr.tcp_session(100.0, f"{LAN}19", "198.51.100.20", 443, up=[tr.rng.randbytes(300_000)], down=[b"ok"], loss=loss)
    found = [f for f in run(tr) if f.kind == "tcp-retransmissions"]
    assert len(found) == expected
    if expected:
        assert found[0].severity == "low" and found[0].evidence["ratio"] > 0.05  # type: ignore[operator]


# the whole ---------------------------------------------------------------------------------------------------------------


def test_findings_are_ordered_by_severity(scenario_result: Result) -> None:
    order = ["info", "low", "medium", "high"]
    levels = [order.index(f.severity) for f in detect(scenario_result)]
    assert levels == sorted(levels, reverse=True)


def test_quiet_capture_has_no_findings() -> None:
    frames, truth = build_scenario(5, 600.0, attacks=False)
    assert truth == [] and detect(analyze_frames(frames)) == []


@pytest.mark.parametrize("seed", [1, 2, 3])
def test_every_injected_thing_is_found(seed: int) -> None:
    frames, truth = build_scenario(seed, 900.0)
    s = score(detect(analyze_frames(frames)), truth)
    assert s.missed == [] and s.false_findings == [] and s.duplicates == 0
    assert s.expected_missed == 1 and s.unexpected_found == 0  # the slow scan stays unseen


def test_harmless_oddities_alone_raise_nothing() -> None:
    tr = Traffic(4)
    tr.background(600.0)
    tr.harmless_oddities(600.0)
    assert run(tr) == []


Maker = Callable[[], Traffic]
