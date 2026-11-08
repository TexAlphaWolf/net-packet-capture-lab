from __future__ import annotations

import json
import re

from conftest import analyze_frames
from pcaplab.analyze import Result
from pcaplab.detect import Finding, detect
from pcaplab.report import Anonymizer, html_page, markdown, min_severity, text_report, timeline_svg, to_json
from pcaplab.synth import LAN, Traffic


def test_text_and_markdown(scenario_result: Result) -> None:
    found = detect(scenario_result)
    text = text_report(scenario_result, found, "T")
    for part in (
        "Capture",
        "Findings",
        "Protocols",
        "Top hosts by bytes",
        "Services by bytes",
        "TCP flows",
        "DNS",
        "TLS server names",
    ):
        assert part in text
    assert "[high  ]" in text and "port scan" in text
    md = markdown(scenario_result, found, "T")
    assert md.startswith("# T") and "## Findings" in md and "- [high]" in md


def test_json_is_complete_and_parseable(scenario_result: Result) -> None:
    doc = json.loads(to_json(scenario_result, detect(scenario_result)))
    assert set(doc) == {
        "capture",
        "protocols",
        "applications",
        "tcp_states",
        "hosts",
        "services",
        "flows",
        "dns",
        "tls_names",
        "findings",
    }
    assert doc["capture"]["packets"] == scenario_result.packets
    assert doc["findings"][0]["severity"] == "high" and "evidence" in doc["findings"][0]
    assert len(doc["flows"]) <= 100 and doc["flows"][0]["bytes"][0] >= 0
    # sorted keys and a final newline: the same input gives the same bytes
    assert to_json(scenario_result, []) == to_json(scenario_result, [])


def test_html_is_one_safe_page(scenario_result: Result) -> None:
    page = html_page(scenario_result, detect(scenario_result), "Report", "demo.pcap")
    assert page.startswith("<!doctype html>") and "default-src 'none'" in page
    assert "<script" not in page.lower() and "http://" not in page and "https://" not in page
    assert "<svg" in page and "Findings" in page and "Biggest flows" in page
    assert page.count("<h1>") == 1


def test_html_escapes_what_came_from_the_network() -> None:
    tr = Traffic(1)
    tr.dns_lookup(10.0, f"{LAN}9", "<script>alert(1)</script>.example.com")
    tr.dns_lookup(11.0, f"{LAN}9", "<b>x</b>.example.com")
    r = analyze_frames(tr.frames)
    page = html_page(r, [Finding("x", "low", "<img src=x>", "<b>d</b>", (), 10.0, 11.0)])
    assert "<script>alert" not in page and "<img src=x>" not in page and "<b>x</b>" not in page
    assert "&lt;script&gt;" in page


def test_empty_capture_pages() -> None:
    r = analyze_frames([])
    assert "Nothing found." in html_page(r, [])
    assert timeline_svg(r, []) == ""
    assert "none" in text_report(r, [])


def test_timeline_marks_findings(scenario_result: Result) -> None:
    svg = timeline_svg(scenario_result, detect(scenario_result))
    assert svg.count("<path") == len(detect(scenario_result)) and "<rect" in svg


def test_min_severity(scenario_result: Result) -> None:
    found = detect(scenario_result)
    high = min_severity(found, "high")
    assert high and {f.severity for f in high} == {"high"} and len(high) < len(found)
    assert min_severity(found, "info") == found


# anonymiser ----------------------------------------------------------------------------------------------------------


def test_anonymiser_removes_addresses_and_names(scenario_result: Result) -> None:
    found = detect(scenario_result)
    out = {
        "text": text_report(scenario_result, found),
        "json": to_json(scenario_result, found),
        "html": html_page(scenario_result, found),
    }
    for name, text in out.items():
        clean = Anonymizer().apply(text, scenario_result)
        assert not re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", clean), name
        assert not re.search(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", clean), name
        assert "example.com" not in clean and "badcdn-example.org" not in clean, name
        assert "host-" in clean and "name-" in clean and "mac-" in clean
    json.loads(Anonymizer().apply(out["json"], scenario_result))  # still valid JSON


def test_anonymiser_labels_are_stable_and_keyed() -> None:
    r = Result()
    r.sni["secret.example.net"] = 1
    text = "10.0.0.1 talks to 10.0.0.2 and 10.0.0.1 again, secret.example.net, SECRET.example.net, aa:bb:cc:00:11:22, 2001:db8::1"
    a = Anonymizer(b"k" * 16).apply(text, r)
    assert a == Anonymizer(b"k" * 16).apply(text, r)  # same key, same labels
    assert a != Anonymizer(b"z" * 16).apply(text, r)  # another key, other labels
    labels = re.findall(r"(?:host|name|mac)-[0-9a-f]{6}", a)
    assert len(labels) == 7 and labels[0] == labels[2]  # 10.0.0.1 twice
    assert labels[3] == labels[4]  # the name, whatever its case
    assert "10.0.0" not in a and "2001" not in a and "secret" not in a.lower()


def test_anonymiser_leaves_other_numbers_alone() -> None:
    r = Result()
    text = "version 1.2.3, port 443, 999.1.1.1, 10:30:15, 300 packets in 1.5 s"
    assert Anonymizer().apply(text, r) == text
