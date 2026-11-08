from __future__ import annotations

from conftest import analyze_frames
from pcaplab.analyze import Analyzer
from pcaplab.decode import ACK, SYN, Decoded
from pcaplab.flows import FlowTable
from pcaplab.synth import Traffic


def one_flow(**kw: object) -> tuple[Traffic, list]:
    tr = Traffic(3)
    tr.tcp_session(100.0, "10.0.0.10", "198.51.100.5", 443, up=[b"hello"], down=[b"world" * 100], **kw)  # type: ignore[arg-type]
    return tr, analyze_frames(tr.frames).flows


def test_closed_flow() -> None:
    _, flows = one_flow(rtt=0.04)
    assert len(flows) == 1
    f = flows[0]
    assert (f.proto, f.a, f.b, f.b_port, f.state, f.service) == (
        "tcp",
        "10.0.0.10",
        "198.51.100.5",
        443,
        "closed",
        "https",
    )
    assert f.syn == 1 and f.synack and f.acked and f.fin == 2 and f.retrans == 0
    assert abs(f.rtt - 0.04) < 1e-6  # type: ignore[operator]
    assert f.data == [5, 500] and f.pkts[0] > 3 and f.pkts[1] > 3
    assert f.total_pkts == sum(f.pkts) and f.total_bytes == sum(f.bytes) and f.duration > 0.1


def test_reset_and_open() -> None:
    assert one_flow(close="rst")[1][0].state == "reset"
    assert one_flow(close="none")[1][0].state == "established"


def test_retransmissions() -> None:
    tr = Traffic(3)
    tr.tcp_session(100.0, "10.0.0.10", "198.51.100.5", 443, up=[b"x" * 14000], down=[b"ok"], loss=1.0)
    f = analyze_frames(tr.frames).flows[0]
    assert f.data_segments == 22 and f.retrans == 11 and f.retrans_ratio == 0.5  # 11 segments, each sent twice
    _, flows = one_flow()
    assert flows[0].retrans_ratio == 0.0


def test_scan_states() -> None:
    tr = Traffic(3)
    tr.syn_scan("203.0.113.9", ["10.0.0.5"], [1, 2], 100.0, 1, {("10.0.0.5", 1)})  # 1 open (half-open), 2 closed
    tr.syn_scan("203.0.113.9", ["10.0.0.5"], [3], 110.0, 1, drop=True)
    tr.syn_scan("203.0.113.9", ["10.0.0.5"], [4], 120.0, 1, {("10.0.0.5", 4)}, mode="connect")
    states = {f.b_port: f.state for f in analyze_frames(tr.frames).flows}
    assert states == {1: "half-open", 2: "refused", 3: "unanswered", 4: "reset"}


def test_midstream_and_syn_retransmission() -> None:
    tr = Traffic(3)
    tr.tcp_session(100.0, "10.0.0.10", "198.51.100.5", 443, up=[b"a"], down=[b"b"], close="none")
    flows = analyze_frames(tr.frames[3:]).flows  # the handshake was not captured
    assert flows[0].state == "midstream" and flows[0].rtt is None
    tr = Traffic(3)
    tr.syn_scan("203.0.113.9", ["10.0.0.5"], [80], 100.0, 1, drop=True)
    tr.frames.append(tr.frames[0])  # the same SYN again
    f = analyze_frames(tr.frames).flows[0]
    assert f.syn == 2 and f.retrans == 1


def test_reused_ports_make_two_flows() -> None:
    tr = Traffic(3)
    tr.tcp_session(100.0, "10.0.0.10", "198.51.100.5", 443, sport=50000)
    tr.tcp_session(200.0, "10.0.0.10", "198.51.100.5", 443, sport=50000)
    flows = analyze_frames(tr.frames).flows
    assert len(flows) == 2 and {f.state for f in flows} == {"closed"}


def test_udp_and_icmp_flows() -> None:
    tr = Traffic(3)
    tr.dns_lookup(100.0, "10.0.0.10", "a.example.com")
    tr.udp_frame(110.0, "10.0.0.10", "203.0.113.5", 4000, 9999, b"x")
    tr.ip_frame(120.0, "10.0.0.10", "10.0.0.1", 1, b"\x08\x00\x00\x00\x00\x01\x00\x01")
    by = {(f.proto, f.b_port): f for f in analyze_frames(tr.frames).flows}
    assert by[("udp", 53)].state == "answered" and by[("udp", 53)].service == "dns"
    assert by[("udp", 53)].names == {"a.example.com"}
    assert by[("udp", 9999)].state == "one-way" and by[("udp", 9999)].service == "udp/high"
    assert by[("icmp", 0)].state == "one-way" and by[("icmp", 0)].service == "icmp"


def test_service_of_a_low_port() -> None:
    tr = Traffic(3)
    tr.tcp_session(100.0, "10.0.0.10", "198.51.100.5", 600)
    assert analyze_frames(tr.frames).flows[0].service == "tcp/600"


def test_sequence_numbers_wrap() -> None:
    table = FlowTable()

    def seg(seq: int, n: int, ts: float) -> Decoded:
        return Decoded(
            1,
            ts,
            100,
            100,
            src="10.0.0.1",
            dst="10.0.0.2",
            proto="tcp",
            sport=1,
            dport=2,
            seq=seq,
            flags=ACK,
            payload_len=n,
            ip_version=4,
        )

    for i, seq in enumerate(
        (0xFFFFFF00, 0xFFFFFF00 + 200, 0x00000090, 0x00000090)
    ):  # new data across the wrap, then the same again
        table.add(seg(seq & 0xFFFFFFFF, 200, 100.0 + i))
    f = table.all()[0]
    assert f.data_segments == 4 and f.retrans == 1  # only the last one is a repeat


def test_table_limit_and_other_traffic() -> None:
    table = FlowTable(max_flows=1)
    a = Decoded(1, 1.0, 60, 60, src="10.0.0.1", dst="10.0.0.2", proto="udp", sport=1, dport=2, ip_version=4)
    b = Decoded(2, 2.0, 60, 60, src="10.0.0.3", dst="10.0.0.2", proto="udp", sport=1, dport=2, ip_version=4)
    arp = Decoded(3, 3.0, 60, 60, proto="arp")
    assert table.add(a) is not None and table.add(b) is None and table.add(arp) is None
    assert table.dropped == 1 and len(table.all()) == 1
    an = Analyzer(max_flows=1)
    an.feed(a)
    an.feed(b)
    assert an.result().dropped_flows == 1


def test_syn_flag_helpers() -> None:
    assert SYN == 2 and ACK == 16
