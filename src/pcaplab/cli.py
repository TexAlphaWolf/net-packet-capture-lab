"""Command line: summary, findings, flows, dns, report, filter, sample."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .analyze import Result, analyze_packets, registered_domain
from .decode import decode
from .detect import SEVERITIES, Finding, Thresholds, detect
from .filtering import FilterError, Predicate, compile_filter
from .flows import Flow
from .model import CaptureError, fmt_bytes, fmt_dur, fmt_time
from .reader import CaptureReader
from .report import Anonymizer, flow_label, html_page, markdown, min_severity, text_report, to_json
from .synth import build_scenario, write_capture
from .writer import PcapWriter


class UsageError(Exception):
    pass


def _open(path: str) -> CaptureReader:
    return CaptureReader(sys.stdin.buffer if path == "-" else Path(path))


def _predicate(args: argparse.Namespace) -> Predicate | None:
    return compile_filter(args.filter) if args.filter else None


def _thresholds(args: argparse.Namespace) -> Thresholds:
    return Thresholds(
        allow_hosts=frozenset(args.allow),
        ignore_domains=frozenset(registered_domain(d.lower().strip(".")) for d in args.ignore_domain),
    )


def _analyze(args: argparse.Namespace) -> tuple[Result, list[Finding]]:
    keep = _predicate(args)
    with _open(args.file) as cap:
        result = analyze_packets(cap, keep)
        result.warnings.extend(cap.warnings)
    if result.dropped_flows:
        result.warnings.append(
            f"{result.dropped_flows} packets belonged to flows beyond the table limit and were not followed"
        )
    found = min_severity(detect(result, _thresholds(args)), args.min_severity)
    return result, found


def _emit(text: str, args: argparse.Namespace, result: Result) -> None:
    if getattr(args, "anonymize", False):
        text = Anonymizer().apply(text, result)
    sys.stdout.write(text)


def cmd_summary(args: argparse.Namespace) -> int:
    result, found = _analyze(args)
    _emit(text_report(result, found, f"Capture {args.file}"), args, result)
    return 0


def cmd_findings(args: argparse.Namespace) -> int:
    result, found = _analyze(args)
    if args.json:
        doc = json.loads(to_json(result, found))["findings"]
        _emit(json.dumps(doc, indent=2, sort_keys=True) + "\n", args, result)
    elif not found:
        _emit("no findings\n", args, result)
    else:
        lines = []
        for f in found:
            lines.append(
                f"[{f.severity}] {f.title}\n    {f.detail}\n    {fmt_time(f.first)}"
                + (f" to {fmt_time(f.last)}" if f.last - f.first >= 1 else "")
            )
        _emit("\n".join(lines) + "\n", args, result)
    return 1 if found else 0


SORTS = {
    "bytes": lambda f: -f.total_bytes,
    "packets": lambda f: -f.total_pkts,
    "duration": lambda f: -f.duration,
    "time": lambda f: f.first,
}


def cmd_flows(args: argparse.Namespace) -> int:
    result, _found = _analyze(args)
    flows: list[Flow] = result.flows
    if args.state:
        flows = [f for f in flows if f.state == args.state]
    flows = sorted(flows, key=SORTS[args.sort])[: args.top]
    rows = [
        (
            fmt_time(f.first),
            flow_label(f),
            f.service,
            f.state,
            str(f.total_pkts),
            fmt_bytes(f.total_bytes),
            fmt_dur(f.duration),
            str(f.retrans),
        )
        for f in flows
    ]
    head = ("START", "FLOW", "SERVICE", "STATE", "PKTS", "BYTES", "TIME", "RETR")
    widths = [max(len(h), *(len(r[i]) for r in rows)) if rows else len(h) for i, h in enumerate(head)]
    lines = ["  ".join(h.ljust(w) for h, w in zip(head, widths, strict=True)).rstrip()]
    lines += ["  ".join(c.ljust(w) for c, w in zip(r, widths, strict=True)).rstrip() for r in rows]
    _emit("\n".join(lines) + "\n", args, result)
    return 0


def cmd_dns(args: argparse.Namespace) -> int:
    result, _found = _analyze(args)
    lines = ["answers: " + (", ".join(f"{k} {v}" for k, v in result.dns_rcodes.most_common()) or "none seen"), ""]
    lines += [f"{c:>7}  {n}" for n, c in result.dns_queries.most_common(args.top)]
    if result.sni:
        lines += ["", "TLS server names:"] + [f"{c:>7}  {n}" for n, c in result.sni.most_common(args.top)]
    _emit("\n".join(lines) + "\n", args, result)
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    result, found = _analyze(args)
    out = Path(args.output)
    fmt = args.format or {".html": "html", ".md": "md", ".json": "json"}.get(out.suffix.lower(), "text")
    title = f"Capture report: {Path(args.file).name}" if args.file != "-" else "Capture report"
    text = {
        "html": lambda: html_page(result, found, title),
        "md": lambda: markdown(result, found, title),
        "json": lambda: to_json(result, found),
        "text": lambda: text_report(result, found, title),
    }[fmt]()
    if args.anonymize:
        text = Anonymizer().apply(text, result)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8")
    print(f"wrote {out} ({result.packets} packets, {len(found)} findings)")
    return 0


def cmd_filter(args: argparse.Namespace) -> int:
    keep = compile_filter(args.expression)
    with _open(args.file) as cap:
        out: PcapWriter | None = None
        link = None
        try:
            for pkt in cap:
                if link is None:
                    link = pkt.linktype
                elif pkt.linktype != link:
                    raise UsageError("the capture mixes link types, which a classic pcap file cannot hold")
                if keep(decode(pkt)):
                    if out is None:
                        out = PcapWriter(args.output, link)
                    out.write(pkt)
            if out is None:
                out = PcapWriter(args.output, link or 1)  # an empty file is still a valid capture
        finally:
            if out is not None:
                out.close()
        for w in cap.warnings:
            print(f"warning: {w}", file=sys.stderr)
    print(f"wrote {args.output} ({out.count} packets)")
    return 0


def cmd_sample(args: argparse.Namespace) -> int:
    frames, truth = build_scenario(args.seed, args.duration)
    write_capture(args.output, frames, args.format)
    print(f"wrote {args.output} ({len(frames)} packets, {args.duration:.0f} s, {len(truth)} things injected)")
    if args.truth:
        doc = [{"kind": t.kind, "host": t.host, "detectable": t.detectable, **t.info} for t in truth]
        Path(args.truth).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {args.truth}")
    return 0


def _common(p: argparse.ArgumentParser, *, findings: bool = True) -> None:
    p.add_argument("file", help="a pcap or pcapng file, or - for standard input")
    p.add_argument("-f", "--filter", help="keep only the packets that match, e.g. 'tcp and port 443'")
    if findings:
        p.add_argument(
            "--allow",
            action="append",
            default=[],
            metavar="HOST",
            help="a host that is expected to scan or poll (repeatable)",
        )
        p.add_argument(
            "--ignore-domain",
            action="append",
            default=[],
            metavar="DOMAIN",
            help="a domain with many odd names that is fine (repeatable)",
        )
        p.add_argument("--min-severity", choices=SEVERITIES, default="info")
    p.add_argument(
        "--anonymize", action="store_true", help="replace addresses and names with labels, to publish the output"
    )


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="pcaplab", description="Read packet captures and find what looks wrong.")
    ap.add_argument("--version", action="version", version=f"pcaplab {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("summary", help="what is in the capture, and what looks wrong")
    _common(p)
    p.set_defaults(fn=cmd_summary)

    p = sub.add_parser("findings", help="only what looks wrong; exit code 1 if there is anything")
    _common(p)
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_findings)

    p = sub.add_parser("flows", help="the conversations, biggest first")
    _common(p)
    p.add_argument("--top", type=int, default=20)
    p.add_argument("--sort", choices=sorted(SORTS), default="bytes")
    p.add_argument(
        "--state", help="only flows in this state (established, closed, reset, refused, unanswered, half-open, ...)"
    )
    p.set_defaults(fn=cmd_flows)

    p = sub.add_parser("dns", help="the names asked, and the TLS server names seen")
    _common(p)
    p.add_argument("--top", type=int, default=20)
    p.set_defaults(fn=cmd_dns)

    p = sub.add_parser("report", help="write a report file (html, md, json or text)")
    _common(p)
    p.add_argument("-o", "--output", required=True)
    p.add_argument("--format", choices=["html", "md", "json", "text"], help="default: from the extension of the output")
    p.set_defaults(fn=cmd_report)

    p = sub.add_parser("filter", help="copy the packets that match an expression to a new pcap file")
    p.add_argument("file")
    p.add_argument("expression")
    p.add_argument("-o", "--output", required=True)
    p.set_defaults(fn=cmd_filter)

    p = sub.add_parser("sample", help="write a synthetic capture with known scans, tunnels, beacons and so on")
    p.add_argument("-o", "--output", required=True)
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--duration", type=float, default=1800.0, help="seconds of traffic (default 1800)")
    p.add_argument("--format", choices=["pcap", "pcapng"], default="pcap")
    p.add_argument("--truth", metavar="FILE", help="also write what was injected, as JSON")
    p.set_defaults(fn=cmd_sample)
    return ap


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if getattr(args, "duration", 1) <= 0:
            raise UsageError("--duration must be positive")
        if getattr(args, "top", 1) < 1:
            raise UsageError("--top must be at least 1")
        return int(args.fn(args))
    except (UsageError, CaptureError, FilterError) as exc:
        print(f"pcaplab: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"pcaplab: {exc.strerror or exc}" + (f": {exc.filename}" if exc.filename else ""), file=sys.stderr)
        return 2
    except BrokenPipeError:  # pragma: no cover (output piped into head)
        return 0
