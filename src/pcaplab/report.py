"""Reports: text, Markdown, JSON and one self-contained HTML page (no script, no external file), and the anonymiser."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
import secrets
from collections import Counter
from html import escape

from .analyze import Result
from .detect import SEVERITIES, Finding
from .flows import Flow
from .model import fmt_bytes, fmt_dur, fmt_pct, fmt_time

TOP = 10


class Anonymizer:
    """Replaces IP addresses, MAC addresses and the names seen in the capture with short labels, so a report can be
    published. The label comes from an HMAC with a key: the same value gets the same label in one report (the story can
    still be followed), and nobody can go back from a label to the value. Without ``key`` a random one is used."""

    def __init__(self, key: bytes | None = None) -> None:
        self.key = key or secrets.token_bytes(16)

    def _label(self, kind: str, value: str) -> str:
        return f"{kind}-{hmac.new(self.key, value.encode(), hashlib.sha256).hexdigest()[:6]}"

    _MAC = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:])")
    _V4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.]*\d)")
    _V6 = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])")

    def apply(self, text: str, r: Result) -> str:
        """Anonymise ``text`` (a finished report); ``r`` supplies the names to look for."""
        names = {*r.dns_queries, *r.sni, *r.http_hosts, *(a.domain for a in r.dns_agg.values())}
        for nx in r.nx.values():
            names.update(nx.names)
        for f in r.flows:
            names.update(f.names)
        names = {n for n in names if n}
        if names:
            ordered = sorted(names, key=len, reverse=True)[:20000]
            pat = re.compile(
                r"(?<![A-Za-z0-9.-])(?:" + "|".join(re.escape(n) for n in ordered) + r")(?![A-Za-z0-9-])", re.I
            )
            text = pat.sub(lambda m: self._label("name", m.group(0).lower()), text)
        text = self._MAC.sub(lambda m: self._label("mac", m.group(0).lower()), text)

        def v6(m: re.Match[str]) -> str:
            try:
                return self._label("host", ipaddress.IPv6Address(m.group(0)).compressed)
            except ValueError:
                return m.group(0)

        def v4(m: re.Match[str]) -> str:
            try:
                return self._label("host", ipaddress.IPv4Address(m.group(0)).compressed)
            except ValueError:
                return m.group(0)

        return self._V4.sub(v4, self._V6.sub(v6, text))


# numbers --------------------------------------------------------------------------------------------------------


def top_hosts(r: Result, n: int = TOP) -> list[tuple[str, list[int]]]:
    return sorted(r.hosts.items(), key=lambda kv: -(kv[1][1] + kv[1][3]))[:n]


def top_services(r: Result, n: int = TOP) -> list[tuple[str, int, int]]:
    """(service, flows, bytes) by bytes."""
    flows: Counter[str] = Counter()
    size: Counter[str] = Counter()
    for f in r.flows:
        flows[f.service] += 1
        size[f.service] += f.total_bytes
    return [(s, flows[s], b) for s, b in size.most_common(n)]


def top_flows(r: Result, n: int = TOP) -> list[Flow]:
    return sorted(r.flows, key=lambda f: -f.total_bytes)[:n]


def tcp_states(r: Result) -> Counter[str]:
    return Counter(f.state for f in r.flows if f.proto == "tcp")


def flow_label(f: Flow) -> str:
    left = f"{f.a}:{f.a_port}" if f.a_port else f.a
    right = f"{f.b}:{f.b_port}" if f.b_port else f.b
    return f"{f.proto} {left} -> {right}"


def _kinds(r: Result) -> list[tuple[str, int]]:
    return r.kinds.most_common()


# text and Markdown ------------------------------------------------------------------------------------------------


def _lines(r: Result, findings: list[Finding], md: bool, title: str) -> list[str]:
    h1, h2 = ("# ", "## ") if md else ("", "")
    out = [f"{h1}{title}", ""]
    out.append(f"{h2}Capture" if md else "Capture")
    out.append(
        f"{r.packets} packets, {fmt_bytes(r.bytes)}, {fmt_dur(r.duration)} "
        f"({fmt_time(r.first)} to {fmt_time(r.last)}); {len(r.hosts)} hosts, {len(r.flows)} flows"
    )
    if r.errors:
        out.append(
            f"{sum(r.errors.values())} packets could not be decoded fully: "
            + ", ".join(f"{k} ({v})" for k, v in r.errors.most_common(3))
        )
    out.append("")
    out.append("Findings" if not md else f"{h2}Findings")
    if not findings:
        out.append("none")
    for f in findings:
        out.append(
            f"- [{f.severity}] {f.title}: {f.detail}" if md else f"  [{f.severity:<6}] {f.title}\n           {f.detail}"
        )
    out.append("")
    out.append(f"{h2}Protocols" if md else "Protocols")
    out.extend(("- " if md else "  ") + f"{k}: {v} packets ({fmt_pct(v, r.packets)})" for k, v in _kinds(r))
    out.append("")
    out.append(f"{h2}Top hosts by bytes" if md else "Top hosts by bytes")
    for ip, (po, bo, pi, bi) in top_hosts(r):
        out.append(
            ("- " if md else "  ")
            + f"{ip}: {fmt_bytes(bo + bi)} ({po + pi} packets; {fmt_bytes(bo)} sent, {fmt_bytes(bi)} received)"
        )
    out.append("")
    out.append(f"{h2}Services by bytes" if md else "Services by bytes")
    out.extend(("- " if md else "  ") + f"{s}: {fmt_bytes(b)} in {n} flows" for s, n, b in top_services(r))
    states = tcp_states(r)
    if states:
        out.append("")
        out.append(f"{h2}TCP flows" if md else "TCP flows")
        out.append(("- " if md else "  ") + ", ".join(f"{k} {v}" for k, v in states.most_common()))
    if r.dns_queries:
        out.append("")
        out.append(f"{h2}DNS" if md else "DNS")
        out.append(
            ("- " if md else "  ")
            + "answers: "
            + (", ".join(f"{k} {v}" for k, v in r.dns_rcodes.most_common()) or "none seen")
        )
        out.extend(("- " if md else "  ") + f"{n}: {c} queries" for n, c in r.dns_queries.most_common(TOP))
    if r.sni:
        out.append("")
        out.append(f"{h2}TLS server names" if md else "TLS server names")
        out.extend(("- " if md else "  ") + f"{n}: {c}" for n, c in r.sni.most_common(TOP))
    for w in r.warnings:
        out.append("")
        out.append(f"warning: {w}")
    return out


def text_report(r: Result, findings: list[Finding], title: str = "Capture report") -> str:
    return "\n".join(_lines(r, findings, False, title)) + "\n"


def markdown(r: Result, findings: list[Finding], title: str = "Capture report") -> str:
    return "\n".join(_lines(r, findings, True, title)) + "\n"


def to_json(r: Result, findings: list[Finding]) -> str:
    doc = {
        "capture": {
            "packets": r.packets,
            "bytes": r.bytes,
            "first": r.first,
            "last": r.last,
            "duration": round(r.duration, 6),
            "hosts": len(r.hosts),
            "flows": len(r.flows),
            "undecoded": dict(r.errors),
            "warnings": r.warnings,
        },
        "protocols": dict(r.kinds),
        "applications": dict(r.apps),
        "tcp_states": dict(tcp_states(r)),
        "hosts": [
            {"ip": ip, "packets_out": a, "bytes_out": b, "packets_in": c, "bytes_in": d}
            for ip, (a, b, c, d) in top_hosts(r, 50)
        ],
        "services": [{"service": s, "flows": n, "bytes": b} for s, n, b in top_services(r, 50)],
        "flows": [
            {
                "flow": flow_label(f),
                "state": f.state,
                "service": f.service,
                "first": f.first,
                "seconds": round(f.duration, 6),
                "packets": f.pkts,
                "bytes": f.bytes,
                "retransmissions": f.retrans,
                "rtt_ms": None if f.rtt is None else round(f.rtt * 1000, 3),
                "names": sorted(f.names)[:5],
            }
            for f in top_flows(r, 100)
        ],
        "dns": {"rcodes": dict(r.dns_rcodes), "top_names": r.dns_queries.most_common(50)},
        "tls_names": r.sni.most_common(50),
        "findings": [
            {
                "kind": f.kind,
                "severity": f.severity,
                "title": f.title,
                "detail": f.detail,
                "hosts": list(f.hosts),
                "first": f.first,
                "last": f.last,
                "evidence": f.evidence,
            }
            for f in findings
        ],
    }
    return json.dumps(doc, indent=2, sort_keys=True) + "\n"


# HTML ---------------------------------------------------------------------------------------------------------------

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--fg:#1c2330;--muted:#667085;--line:#d9dee7;--accent:#2563eb;--warn:#b45309;--bad:#c0262d;
--ok:#15803d;--bar:#c7d6f8}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#0f141b;--card:#171e28;--fg:#e5e9f0;--muted:#9aa5b5;
--line:#2c3644;--accent:#6ea0ff;--warn:#f0a43a;--bad:#ff6b72;--ok:#4ade80;--bar:#2b3f66}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",
Roboto,sans-serif}main{max-width:1000px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:0 0 10px}
.sub{color:var(--muted);margin:0 0 20px}.card{background:var(--card);border:1px solid var(--line);border-radius:10px;
padding:16px 18px;margin:16px 0}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px}.kpi b{display:block;font-size:22px;
font-variant-numeric:tabular-nums}.kpi span{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.05em}
table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;padding:5px 10px;border-bottom:1px solid var(--line)}
th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
font-size:13px}.pill{display:inline-block;padding:0 9px;border-radius:99px;font-size:11px;font-weight:700;text-transform:uppercase;
border:1px solid currentColor;margin-right:8px}.high,.bad{color:var(--bad)}.medium,.warn{color:var(--warn)}.low,.info,.muted{color:var(--muted)}
ul.f{list-style:none;margin:0;padding:0}ul.f li{padding:8px 0;border-bottom:1px solid var(--line)}ul.f li:last-child{border:0}
ul.f small{display:block;color:var(--muted);margin-top:2px}.cols{display:grid;grid-template-columns:minmax(0,1fr);gap:0 24px}
@media (min-width:860px){.cols{grid-template-columns:1fr 1fr}}
.bar{display:flex;align-items:center;gap:8px;margin:3px 0;font-size:14px}.bar i{display:block;height:10px;background:var(--accent);
border-radius:3px;min-width:2px}.bar span{width:120px;flex:none}.bar em{color:var(--muted);font-style:normal;font-size:12px}
svg{max-width:100%;height:auto;display:block}.axis{fill:var(--muted);font-size:11px}.col{fill:var(--bar)}
"""

_SEV_COLOR = {"high": "var(--bad)", "medium": "var(--warn)", "low": "var(--muted)", "info": "var(--muted)"}


def timeline_svg(r: Result, findings: list[Finding], cols: int = 200) -> str:
    """Packets over time as columns, with a mark above the column where each finding starts."""
    w, h, top = 900, 130, 24
    if not r.timeline:
        return ""
    t0, t1 = int(r.first), int(r.last)
    step = max(1, -(-(t1 - t0 + 1) // cols))
    buckets: Counter[int] = Counter()
    for sec, (pk, _b) in r.timeline.items():
        buckets[(sec - t0) // step] += pk
    n = (t1 - t0) // step + 1
    peak = max(buckets.values())
    bw = w / n
    bars = []
    for i in range(n):
        v = buckets.get(i, 0)
        if v:
            bh = max(1.0, (h - top - 16) * v / peak)
            bars.append(
                f'<rect class="col" x="{i * bw:.1f}" y="{h - 16 - bh:.1f}" width="{max(1.0, bw - 0.5):.1f}" height="{bh:.1f}"/>'
            )
    marks = []
    for f in findings:
        x = ((int(f.first) - t0) // step + 0.5) * bw
        marks.append(
            f'<path d="M{x - 5:.1f} 2 L{x + 5:.1f} 2 L{x:.1f} 12 Z" fill="{_SEV_COLOR.get(f.severity, "var(--muted)")}">'
            f"<title>{escape(f.title)}</title></path>"
        )
    label = f"{fmt_time(r.first)}   ({fmt_dur(step)} per column, tallest = {peak} packets)"
    return (
        f'<svg viewBox="0 0 {w} {h}" role="img" aria-label="packets over time, with the findings marked">'
        + "".join(bars)
        + "".join(marks)
        + f'<text class="axis" x="0" y="{h - 3}">{escape(label)}</text></svg>'
    )


def _bars(rows: list[tuple[str, float, str]]) -> str:
    if not rows:
        return '<p class="muted">nothing</p>'
    peak = max(v for _, v, _ in rows) or 1
    return "".join(
        f'<div class="bar"><span class="mono">{escape(name)}</span><i style="width:{100 * v / peak * 0.55:.1f}%"></i><em>{escape(txt)}</em></div>'
        for name, v, txt in rows
    )


def html_page(r: Result, findings: list[Finding], title: str = "Capture report", source: str = "") -> str:
    kpis = [
        (f"{r.packets:,}", "packets"),
        (fmt_bytes(r.bytes), "on the wire"),
        (fmt_dur(r.duration), "duration"),
        (str(len(r.hosts)), "hosts"),
        (f"{len(r.flows):,}", "flows"),
        (str(len(findings)), "findings"),
    ]
    fl = (
        "".join(
            f'<li><span class="pill {escape(f.severity)}">{escape(f.severity)}</span><b>{escape(f.title)}</b>'
            f"<small>{escape(f.detail)} · {escape(fmt_time(f.first))}</small></li>"
            for f in findings
        )
        or '<li class="muted">Nothing found.</li>'
    )
    protos = _bars([(k, v, f"{v:,} ({fmt_pct(v, r.packets)})") for k, v in _kinds(r)])
    services = _bars([(s, b, f"{fmt_bytes(b)} · {n} flows") for s, n, b in top_services(r, 8)])
    hosts = "".join(
        f'<tr><td class="mono">{escape(ip)}</td><td class="n">{fmt_bytes(bo)}</td><td class="n">{fmt_bytes(bi)}</td><td class="n">{po + pi:,}</td></tr>'
        for ip, (po, bo, pi, bi) in top_hosts(r, 8)
    )
    flows = "".join(
        f'<tr><td class="mono">{escape(flow_label(f))}</td><td>{escape(f.service)}</td><td>{escape(f.state)}</td>'
        f'<td class="n">{fmt_bytes(f.total_bytes)}</td><td class="n">{fmt_dur(f.duration)}</td></tr>'
        for f in top_flows(r, 8)
    )
    dns = "".join(
        f'<tr><td class="mono">{escape(n)}</td><td class="n">{c}</td></tr>' for n, c in r.dns_queries.most_common(8)
    )
    tls = "".join(f'<tr><td class="mono">{escape(n)}</td><td class="n">{c}</td></tr>' for n, c in r.sni.most_common(8))
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\">"
        f"<title>{escape(title)}</title><style>{CSS}</style></head><body><main>"
        f'<h1>{escape(title)}</h1><p class="sub">{escape(source)}{" · " if source else ""}{escape(fmt_time(r.first))} to '
        f"{escape(fmt_time(r.last))}</p>"
        '<div class="card kpis">'
        + "".join(f"<div class='kpi'><b>{escape(v)}</b><span>{escape(k)}</span></div>" for v, k in kpis)
        + "</div>"
        f'<div class="card"><h2>Findings</h2><ul class="f">{fl}</ul></div>'
        f'<div class="card"><h2>Packets over time</h2>{timeline_svg(r, findings)}</div>'
        f'<div class="cols"><div class="card"><h2>Protocols</h2>{protos}</div><div class="card"><h2>Services by bytes</h2>{services}</div></div>'
        '<div class="card"><h2>Top hosts</h2><table><thead><tr><th>Host</th><th class="n">Sent</th><th class="n">Received</th>'
        f'<th class="n">Packets</th></tr></thead><tbody>{hosts}</tbody></table></div>'
        '<div class="card"><h2>Biggest flows</h2><table><thead><tr><th>Flow</th><th>Service</th><th>State</th><th class="n">Bytes</th>'
        f'<th class="n">Duration</th></tr></thead><tbody>{flows}</tbody></table></div>'
        + (
            '<div class="cols">'
            f'<div class="card"><h2>DNS names asked</h2><table><tbody>{dns}</tbody></table></div>'
            f'<div class="card"><h2>TLS server names</h2><table><tbody>{tls or "<tr><td class=muted>none</td></tr>"}</tbody></table></div></div>'
            if dns
            else ""
        )
        + "</main></body></html>"
    )


def min_severity(findings: list[Finding], level: str) -> list[Finding]:
    floor = SEVERITIES.index(level)
    return [f for f in findings if SEVERITIES.index(f.severity) >= floor]
