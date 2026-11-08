"""Scores the findings of the detectors against what the generator injected."""

from __future__ import annotations

from dataclasses import dataclass, field

from pcaplab.detect import Finding
from pcaplab.synth import Truth


@dataclass
class Score:
    found: dict[str, int] = field(default_factory=dict)  # truths found, by kind
    total: dict[str, int] = field(default_factory=dict)  # truths that should be found, by kind
    missed: list[Truth] = field(default_factory=list)
    false_findings: list[Finding] = field(default_factory=list)  # matched no truth
    duplicates: int = 0  # two findings for one truth
    expected_missed: int = 0  # truths below the thresholds on purpose
    unexpected_found: int = 0  # ... that were found anyway


def score(findings: list[Finding], truth: list[Truth]) -> Score:
    s = Score()
    used: set[int] = set()
    for f in findings:
        hit = next((i for i, t in enumerate(truth) if t.kind == f.kind and t.host == f.hosts[0]), None)
        if hit is None:
            s.false_findings.append(f)
        elif hit in used:
            s.duplicates += 1
        else:
            used.add(hit)
    for i, t in enumerate(truth):
        if not t.detectable:
            s.expected_missed += 1
            s.unexpected_found += i in used
            continue
        s.total[t.kind] = s.total.get(t.kind, 0) + 1
        if i in used:
            s.found[t.kind] = s.found.get(t.kind, 0) + 1
        else:
            s.missed.append(t)
    return s
