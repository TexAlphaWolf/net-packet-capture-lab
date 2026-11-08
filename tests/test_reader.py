from __future__ import annotations

import io
import struct
from pathlib import Path

import pytest

from pcaplab.model import CaptureError
from pcaplab.reader import CaptureReader
from pcaplab.synth import _block, pcap_bytes, pcapng_bytes

FRAMES = [(1_760_000_000.25, b"\x01" * 60), (1_760_000_001.5, b"\x02" * 70), (1_760_000_002.000125, b"\x03" * 64)]


def read(data: bytes) -> tuple[list[tuple[float, bytes, int]], CaptureReader]:
    with CaptureReader(data) as cap:
        pkts = [(p.ts, p.data, p.index) for p in cap]
        return pkts, cap


@pytest.mark.parametrize("nano", [False, True])
@pytest.mark.parametrize("big", [False, True])
def test_pcap_variants(nano: bool, big: bool) -> None:
    pkts, cap = read(pcap_bytes(FRAMES, nano=nano, big=big))
    assert cap.format == "pcap" and not cap.warnings and cap.linktypes == {1}
    assert [p[1] for p in pkts] == [f[1] for f in FRAMES]
    assert [p[2] for p in pkts] == [1, 2, 3]
    for (ts, _, _), (want, _) in zip(pkts, FRAMES, strict=True):
        assert abs(ts - want) < 1e-6


@pytest.mark.parametrize("big", [False, True])
@pytest.mark.parametrize("res", [3, 6, 9])
def test_pcapng_variants(big: bool, res: int) -> None:
    frames = [(1_760_000_000.25, b"\x01" * 60), (1_760_000_001.5, b"\x02" * 71)]  # 71: block padding
    pkts, cap = read(pcapng_bytes(frames, big=big, tsresol=res))
    assert cap.format == "pcapng" and not cap.warnings
    assert [p[1] for p in pkts] == [f[1] for f in frames]
    for (ts, _, _), (want, _) in zip(pkts, frames, strict=True):
        assert abs(ts - want) < 1e-6


def test_pcapng_binary_resolution() -> None:
    o = "<"
    shb = _block(o, 0x0A0D0D0A, struct.pack(o + "IHHq", 0x1A2B3C4D, 1, 0, -1))
    opt = struct.pack(o + "HH", 9, 1) + bytes([0x8A]) + b"\x00\x00\x00" + struct.pack(o + "HH", 0, 0)  # 2^-10 s
    idb = _block(o, 1, struct.pack(o + "HHI", 1, 0, 65535) + opt)
    ticks = 1_760_000_000 * 1024 + 512
    epb = _block(o, 6, struct.pack(o + "IIIII", 0, ticks >> 32, ticks & 0xFFFFFFFF, 4, 4) + b"abcd")
    pkts, _ = read(shb + idb + epb)
    assert pkts[0][0] == 1_760_000_000.5


def test_pcapng_simple_packet_unknown_block_and_second_section() -> None:
    o = "<"
    shb = _block(o, 0x0A0D0D0A, struct.pack(o + "IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = _block(o, 1, struct.pack(o + "HHI", 1, 0, 100))
    spb = _block(o, 3, struct.pack(o + "I", 200) + b"x" * 100)  # cut to the snap length of the interface
    nrb = _block(o, 4, b"\x00\x00\x00\x00")  # name resolution: skipped
    big = ">"
    shb2 = _block(big, 0x0A0D0D0A, struct.pack(big + "IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb2 = _block(big, 1, struct.pack(big + "HHI", 101, 0, 0))
    spb2 = _block(big, 3, struct.pack(big + "I", 5) + b"hello")
    pkts, cap = read(shb + idb + nrb + spb + shb2 + idb2 + spb2)
    assert [len(p[1]) for p in pkts] == [100, 5]
    assert pkts[0][0] == 0.0
    assert cap.linktypes == {1, 101}


@pytest.mark.parametrize("cut", [1, 7, 40, 60])
def test_truncated_pcap_keeps_what_was_read(cut: int) -> None:
    data = pcap_bytes(FRAMES)
    pkts, cap = read(data[:-cut])
    assert 1 <= len(pkts) < 3
    assert (cap.warnings and "cut off" in cap.warnings[0]) or "ends inside" in cap.warnings[0]


def test_truncated_pcap_record_header() -> None:
    data = pcap_bytes(FRAMES[:1])
    pkts, cap = read(data + b"\x00" * 5)
    assert len(pkts) == 1 and "header of record 2" in cap.warnings[0]


@pytest.mark.parametrize("cut", [3, 30, 90])
def test_truncated_pcapng(cut: int) -> None:
    pkts, cap = read(pcapng_bytes(FRAMES)[:-cut])
    assert len(pkts) < 3
    assert cap.warnings


def test_bad_files() -> None:
    for data, msg in [
        (b"", "too short"),
        (b"ab", "too short"),
        (b"GIF89a" + b"\x00" * 40, "unknown magic"),
        (pcap_bytes([])[:10], "cut off"),
    ]:
        with pytest.raises(CaptureError, match=msg), CaptureReader(data) as cap:
            list(cap)


def test_damaged_record_is_refused() -> None:
    head = pcap_bytes([])
    with (
        pytest.raises(CaptureError, match="damaged"),
        CaptureReader(head + struct.pack("<IIII", 1, 0, 0x7FFFFFFF, 10)) as cap,
    ):
        list(cap)


def test_damaged_pcapng() -> None:
    o = "<"
    shb = _block(o, 0x0A0D0D0A, struct.pack(o + "IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = _block(o, 1, struct.pack(o + "HHI", 1, 0, 100))
    cases = {
        "impossible length": shb + struct.pack(o + "II", 6, 5) + b"\x00" * 8,
        "never described": shb + _block(o, 6, struct.pack(o + "IIIII", 3, 0, 0, 4, 4) + b"abcd"),
        "too short": shb + idb + _block(o, 6, b"\x00" * 8),
        "shorter than its captured": shb + idb + _block(o, 6, struct.pack(o + "IIIII", 0, 0, 0, 99, 99) + b"abcd"),
        "without an interface": shb + _block(o, 3, struct.pack(o + "I", 5) + b"hello"),
        "interface block is too short": shb + _block(o, 1, b"\x01"),
    }
    for msg, data in cases.items():
        with pytest.raises(CaptureError, match=msg), CaptureReader(data) as cap:
            list(cap)
    bad_magic = struct.pack("<II", 0x0A0D0D0A, 28) + b"\x00\x00\x00\x00" + b"\x00" * 20
    with pytest.raises(CaptureError, match="byte-order"), CaptureReader(bad_magic) as cap:
        list(cap)


def test_files_and_streams(tmp_path: Path) -> None:
    path = tmp_path / "a.pcap"
    path.write_bytes(pcap_bytes(FRAMES))
    with CaptureReader(path) as cap:
        assert len(list(cap)) == 3
    with CaptureReader(str(path)) as cap:
        assert len(list(cap)) == 3
    stream = io.BytesIO(pcap_bytes(FRAMES))
    with CaptureReader(stream) as cap:
        assert len(list(cap)) == 3
    assert not stream.closed  # a stream given by the caller is not closed by the reader
    with pytest.raises(CaptureError, match="cannot open"):
        CaptureReader(tmp_path / "missing.pcap")


def test_empty_capture_is_valid() -> None:
    pkts, cap = read(pcap_bytes([]))
    assert pkts == [] and not cap.warnings
    pkts, cap = read(pcapng_bytes([]))
    assert pkts == [] and not cap.warnings
