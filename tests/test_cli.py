from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

from pcaplab.cli import main
from pcaplab.reader import CaptureReader
from pcaplab.synth import pcap_bytes


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def test_version_and_help(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0 and "pcaplab 1.0.0" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        main([])


def test_sample_is_reproducible(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    a, b, c = tmp_path / "a.pcap", tmp_path / "b.pcap", tmp_path / "c.pcap"
    code, out, _ = run(capsys, "sample", "-o", str(a), "--duration", "300", "--truth", str(tmp_path / "t.json"))
    assert code == 0 and "12 things injected" in out
    run(capsys, "sample", "-o", str(b), "--duration", "300")
    run(capsys, "sample", "-o", str(c), "--duration", "300", "--seed", "2")
    assert a.read_bytes() == b.read_bytes() and a.read_bytes() != c.read_bytes()
    truth = json.loads((tmp_path / "t.json").read_text())
    assert {t["kind"] for t in truth} >= {"port-scan", "dns-tunnel", "beacon", "arp-conflict"}
    assert next(t for t in truth if not t["detectable"])["shape"] == "slow"
    run(capsys, "sample", "-o", str(tmp_path / "n.pcapng"), "--duration", "120", "--format", "pcapng")
    with CaptureReader(tmp_path / "n.pcapng") as cap:
        assert cap.format == "pcapng"


def test_findings_exit_code_and_options(scenario_file: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "findings", str(scenario_file))
    assert code == 1 and "[high]" in out and "[low]" in out and "port scan from 203.0.113.50" in out
    code, out, _ = run(capsys, "findings", str(scenario_file), "--min-severity", "high")
    assert code == 1 and "[medium]" not in out
    code, out, _ = run(capsys, "findings", str(scenario_file), "-f", "udp and not dns")
    assert code == 0 and out == "no findings\n"
    code, out, _ = run(
        capsys, "findings", str(scenario_file), "--json", "--allow", "203.0.113.50", "--allow", "10.0.0.77"
    )
    doc = json.loads(out)
    assert code == 1 and all(f["hosts"][0] not in ("203.0.113.50", "10.0.0.77") for f in doc)
    code, out, _ = run(
        capsys, "findings", str(scenario_file), "--ignore-domain", "t.badcdn-example.org", "--min-severity", "high"
    )
    assert "DNS tunnel" not in out  # a full name is cut down to its registered domain


def test_summary_flows_dns(scenario_file: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "summary", str(scenario_file))
    assert code == 0 and "Findings" in out and "Top hosts by bytes" in out
    code, out, _ = run(capsys, "flows", str(scenario_file), "--top", "3")
    assert code == 0 and len(out.splitlines()) == 4 and out.startswith("START")
    code, out, _ = run(capsys, "flows", str(scenario_file), "--state", "refused", "--sort", "time", "--top", "2")
    assert code == 0 and out.count("refused") == 2
    code, out, _ = run(capsys, "flows", str(scenario_file), "--state", "nonsense")
    assert code == 0 and len(out.splitlines()) == 1
    code, out, _ = run(capsys, "dns", str(scenario_file), "--top", "3")
    assert code == 0 and "NOERROR" in out and "TLS server names" in out
    code, out, _ = run(capsys, "dns", str(scenario_file), "-f", "icmp")
    assert "none seen" in out


def test_anonymize_flag(scenario_file: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "summary", str(scenario_file), "--anonymize")
    assert code == 0 and "10.0.0." not in out and "example.com" not in out and "host-" in out


def test_report_formats(scenario_file: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    for name, marker in (
        ("r.html", "<!doctype html>"),
        ("r.md", "# Capture report"),
        ("r.json", '"findings"'),
        ("r.txt", "Capture report"),
    ):
        code, out, _ = run(capsys, "report", str(scenario_file), "-o", str(tmp_path / "out" / name))
        assert code == 0 and "wrote" in out
        assert marker in (tmp_path / "out" / name).read_text(encoding="utf-8")
    code, _, _ = run(capsys, "report", str(scenario_file), "-o", str(tmp_path / "x.dat"), "--format", "md")
    assert (tmp_path / "x.dat").read_text().startswith("# ")
    code, _, _ = run(capsys, "report", str(scenario_file), "-o", str(tmp_path / "anon.html"), "--anonymize")
    assert "10.0.0.5" not in (tmp_path / "anon.html").read_text()


def test_filter_command(scenario_file: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out_file = tmp_path / "dns.pcap"
    code, out, _ = run(capsys, "filter", str(scenario_file), "dns and host 10.0.0.23", "-o", str(out_file))
    assert code == 0
    with CaptureReader(out_file) as cap:
        n = sum(1 for _ in cap)
    assert f"({n} packets)" in out and n > 100
    code, out, _ = run(capsys, "filter", str(scenario_file), "host 192.168.99.99", "-o", str(tmp_path / "none.pcap"))
    assert code == 0 and "(0 packets)" in out
    with CaptureReader(tmp_path / "none.pcap") as cap:
        assert list(cap) == []  # an empty capture, but a valid file


def test_filter_refuses_mixed_link_types(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    import struct

    from pcaplab.synth import _block

    o = "<"
    data = (
        _block(o, 0x0A0D0D0A, struct.pack(o + "IHHq", 0x1A2B3C4D, 1, 0, -1))
        + _block(o, 1, struct.pack(o + "HHI", 1, 0, 100))
        + _block(o, 1, struct.pack(o + "HHI", 101, 0, 100))
        + _block(o, 6, struct.pack(o + "IIIII", 0, 0, 1, 4, 4) + b"abcd")
        + _block(o, 6, struct.pack(o + "IIIII", 1, 0, 2, 4, 4) + b"abcd")
    )
    (tmp_path / "m.pcapng").write_bytes(data)
    code, _, err = run(capsys, "filter", str(tmp_path / "m.pcapng"), "ip", "-o", str(tmp_path / "o.pcap"))
    assert code == 2 and "mixes link types" in err


def test_truncated_capture_warns(scenario_file: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cut = tmp_path / "cut.pcap"
    cut.write_bytes(scenario_file.read_bytes()[:-5])
    code, out, _ = run(capsys, "summary", str(cut))
    assert code == 0 and "warning:" in out and "cut off" in out
    code, _, err = run(capsys, "filter", str(cut), "tcp", "-o", str(tmp_path / "o.pcap"))
    assert code == 0 and "warning:" in err


def test_stdin(scenario_file: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    class Stdin:
        buffer = io.BytesIO(pcap_bytes([(1_760_000_000.0, b"\x00" * 60)]))

    monkeypatch.setattr(sys, "stdin", Stdin())
    code, out, _ = run(capsys, "summary", "-")
    assert code == 0 and "1 packets" in out


def test_errors_are_exit_code_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / "bad.pcap").write_bytes(b"this is not a capture, just text\n" * 3)
    cases = [
        ("summary", str(tmp_path / "missing.pcap")),
        ("summary", str(tmp_path / "bad.pcap")),
        ("findings", str(tmp_path / "bad.pcap"), "-f", "tcp and"),
        ("report", str(tmp_path / "bad.pcap"), "-o", str(tmp_path / "x.html")),
        ("flows", str(tmp_path / "bad.pcap"), "--top", "0"),
        ("sample", "-o", str(tmp_path / "x.pcap"), "--duration", "0"),
        ("sample", "-o", str(tmp_path / "no" / "such" / "dir" / "x.pcap")),
    ]
    for argv in cases:
        code, out, err = run(capsys, *argv)
        assert code == 2 and err.startswith("pcaplab:") and out == "", argv
