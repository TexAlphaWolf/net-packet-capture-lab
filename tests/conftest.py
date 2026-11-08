from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from pcaplab.analyze import Result, analyze_packets
from pcaplab.reader import CaptureReader
from pcaplab.synth import Frame, Truth, build_scenario, pcap_bytes


def analyze_frames(frames: list[Frame], **kw: object) -> Result:
    with CaptureReader(pcap_bytes(sorted(frames, key=lambda f: f[0]))) as cap:
        return analyze_packets(cap, **kw)  # type: ignore[arg-type]


@pytest.fixture(scope="session")
def scenario() -> tuple[list[Frame], list[Truth]]:
    return build_scenario(1, 900.0)


@pytest.fixture(scope="session")
def scenario_result(scenario: tuple[list[Frame], list[Truth]]) -> Result:
    return analyze_frames(scenario[0])


@pytest.fixture
def scenario_file(tmp_path: Path, scenario: tuple[list[Frame], list[Truth]]) -> Path:
    path = tmp_path / "demo.pcap"
    path.write_bytes(pcap_bytes(scenario[0]))
    return path
