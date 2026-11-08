"""The numbers quoted in the README must be the ones in docs/report.json, and the documented things must exist."""

from __future__ import annotations

import json
import re
from pathlib import Path

from pcaplab.cli import _parser

ROOT = Path(__file__).resolve().parent.parent
REPORT = json.loads((ROOT / "docs" / "report.json").read_text(encoding="utf-8"))
README = (ROOT / "README.md").read_text(encoding="utf-8")
P, B, C = REPORT["pipeline"], REPORT["boundaries"], REPORT["cost"]


def test_report_is_a_full_run():
    assert REPORT["environment"]["quick"] is False
    assert REPORT["environment"]["seed"] >= 1000
    assert P["captures"] == 40 and P["quiet"]["captures"] == 15


def test_claims_are_true_in_the_report():
    assert REPORT["crosscheck"]["mismatches"] == 0
    assert P["found_total"] == P["truth_total"] == 440 and P["missed"] in (0, [], {})
    assert P["false_findings"] in (0, [])
    assert P["duplicates"] in (0, [])
    assert P["quiet"]["false_findings"] == 0
    assert P["slow_scan"] == {"injected": 40, "found": 0}
    assert REPORT["real"]["fields_different"] == 0


def test_numbers_in_the_readme():
    cc, real = REPORT["crosscheck"], REPORT["real"]
    for text in (
        f"{cc['packets']:,} random packets",
        f"**{cc['fields_compared']:,}** fields",
        f"{real['files']} real",
        f"{real['packets']:,} packets, {real['fields_equal']:,} fields",
        f"{P['captures']} captures of 30 minutes ({P['packets']:,} packets)",
        f"**{P['truth_total']}** injected",
        f"**{P['found_total']} of {P['truth_total']}** found",
        f"{P['quiet']['packets']:,} packets",
    ):
        assert text in README, text
    naive = P["baseline"]
    for kind in ("port-scan", "beacon", "nxdomain-storm", "dns-tunnel"):
        assert (
            f"{naive['alerts'][kind]} alerts ({naive['false'][kind]} false)" in README
            or (f"{naive['alerts'][kind]} ({naive['false'][kind]} false)" in README)
            or re.search(rf"{naive['alerts'][kind]}( alerts)? \({naive['false'][kind]} false\)", README)
        ), kind
    sc = {r["scan_targets"]: r["false_findings"] for r in B["sweep_scan_targets"]}
    assert sc[5] == sc[10] == 60 and sc[15] == 0
    bm = {r["beacon_min"]: r["false_findings"] for r in B["sweep_beacon_min"]}
    assert (bm[3], bm[5], bm[8]) == (155, 113, 0)
    a = C["pcap"]["all"]
    assert f"**{round(a['packets_per_second']):,} packets/s**" in README
    assert f"**{a['max_rss_mib']:.1f} MiB**" in README
    assert f"{round(C['pcap']['read']['packets_per_second']):,} packets/s" in README


def test_documented_commands_exist():
    sub = next(a for a in _parser()._actions if a.dest == "cmd").choices
    for name in ("summary", "findings", "flows", "dns", "report", "filter", "sample"):
        assert name in sub and f"`{name}" in README


def test_links_point_to_files():
    for target in re.findall(r"\]\(((?!http)[^)#]+)\)", README):
        assert (ROOT / target).exists(), target


def test_scaffold_is_gone():
    assert "scaffold" not in README and "planned" not in README.lower()
