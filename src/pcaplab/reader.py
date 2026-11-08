"""Capture files: classic pcap (both byte orders, microsecond and nanosecond) and pcapng. Reads as a stream."""

from __future__ import annotations

import io
import struct
from collections.abc import Iterator
from pathlib import Path
from types import TracebackType
from typing import BinaryIO

from .model import CaptureError, Packet

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6),
    b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9),
    b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}
PCAPNG_SHB = 0x0A0D0D0A
MAX_RECORD = 16 * 1024 * 1024  # a longer record means a damaged file
MAX_BLOCK = 128 * 1024 * 1024


class CaptureReader:
    """``with CaptureReader(path) as cap: for pkt in cap: ...``

    ``format`` is "pcap" or "pcapng" once the first bytes are read; ``warnings`` collects what was wrong but did not
    stop the reading (typically a file cut off in the middle of its last record)."""

    def __init__(self, source: str | Path | bytes | BinaryIO) -> None:
        self.warnings: list[str] = []
        self.format = ""
        self.linktypes: set[int] = set()
        self._own = not hasattr(source, "read")
        if isinstance(source, bytes):
            self._f: BinaryIO = io.BytesIO(source)
        elif isinstance(source, str | Path):
            try:
                self._f = open(source, "rb")  # noqa: SIM115 (closed in __exit__)
            except OSError as exc:
                raise CaptureError(f"cannot open {source}: {exc.strerror or exc}") from exc
        else:
            self._f = source
        self._head = b""
        try:
            self._head = self._f.read(4)
            if len(self._head) < 4:
                raise CaptureError("not a capture file (empty or too short)")
            if self._head in PCAP_MAGICS:
                self.format = "pcap"
            elif struct.unpack("<I", self._head)[0] == PCAPNG_SHB:
                self.format = "pcapng"
            else:
                raise CaptureError("not a pcap or pcapng file (unknown magic number)")
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        if self._own:
            self._f.close()

    def __enter__(self) -> CaptureReader:
        return self

    def __exit__(self, *exc: type[BaseException] | BaseException | TracebackType | None) -> None:
        self.close()

    def __iter__(self) -> Iterator[Packet]:
        return self._pcap() if self.format == "pcap" else self._pcapng()

    # classic pcap -----------------------------------------------------------------------------------------------

    def _pcap(self) -> Iterator[Packet]:
        order, unit = PCAP_MAGICS[self._head]
        rest = self._f.read(20)
        if len(rest) < 20:
            raise CaptureError("pcap header is cut off")
        _major, _minor, _zone, _sig, _snaplen, linktype = struct.unpack(order + "HHiIII", rest)
        self.linktypes.add(linktype)
        rec = struct.Struct(order + "IIII")
        index = 0
        while True:
            head = self._f.read(16)
            if not head:
                return
            if len(head) < 16:
                self.warnings.append(f"file ends inside the header of record {index + 1}")
                return
            sec, frac, caplen, wirelen = rec.unpack(head)
            if caplen > MAX_RECORD:
                raise CaptureError(f"record {index + 1} claims {caplen} bytes: the file is damaged")
            data = self._f.read(caplen)
            if len(data) < caplen:
                self.warnings.append(f"file ends inside record {index + 1} (the last packet is cut off)")
                return
            index += 1
            yield Packet(index, sec + frac * unit, max(wirelen, caplen), linktype, data)

    # pcapng -----------------------------------------------------------------------------------------------------

    def _pcapng(self) -> Iterator[Packet]:
        order = "<"
        ifaces: list[tuple[int, float, int]] = []  # (linktype, seconds per tick, snaplen)
        index = 0
        first = True
        pending = self._head  # the first block type is already read
        while True:
            btype_raw = pending or self._f.read(4)
            pending = b""
            if not btype_raw:
                return
            if len(btype_raw) < 4:
                self.warnings.append("file ends inside a block header")
                return
            if first or struct.unpack("<I", btype_raw)[0] == PCAPNG_SHB:
                # section header: its byte order is in the magic, after the length
                lenraw = self._f.read(4)
                magic = self._f.read(4)
                if len(magic) < 4:
                    self.warnings.append("file ends inside the section header")
                    return
                if magic == b"\x4d\x3c\x2b\x1a":
                    order = "<"
                elif magic == b"\x1a\x2b\x3c\x4d":
                    order = ">"
                else:
                    raise CaptureError("pcapng section header has a bad byte-order magic")
                total = self._block_length(lenraw, order)
                if len(self._f.read(total - 12)) < total - 12:
                    self.warnings.append("file ends inside the section header")
                    return
                ifaces = []
                first = False
                continue
            btype = struct.unpack(order + "I", btype_raw)[0]
            lenraw = self._f.read(4)
            if len(lenraw) < 4:
                self.warnings.append("file ends inside a block header")
                return
            total = self._block_length(lenraw, order)
            raw = self._f.read(total - 8)
            if len(raw) < total - 8:
                self.warnings.append("file ends inside a block (the last packet is cut off)")
                return
            body = raw[:-4]  # the block ends with a copy of its length
            if btype == 1:  # interface description
                ifaces.append(self._interface(body, order))
                self.linktypes.add(ifaces[-1][0])
            elif btype == 6:  # enhanced packet
                if len(body) < 20:
                    raise CaptureError("pcapng packet block is too short")
                iface, hi, lo, caplen, wirelen = struct.unpack(order + "IIIII", body[:20])
                if iface >= len(ifaces):
                    raise CaptureError("pcapng packet refers to an interface that was never described")
                linktype, tick, _snap = ifaces[iface]
                data = body[20 : 20 + caplen]
                if len(data) < caplen:
                    raise CaptureError("pcapng packet block is shorter than its captured length")
                index += 1
                yield Packet(index, ((hi << 32) | lo) * tick, max(wirelen, caplen), linktype, data)
            elif btype == 3:  # simple packet: no time stamp, always interface 0
                if not ifaces or len(body) < 4:
                    raise CaptureError("pcapng simple packet without an interface")
                wirelen = struct.unpack(order + "I", body[:4])[0]
                linktype, _tick, snap = ifaces[0]
                caplen = min(wirelen, len(body) - 4, snap or MAX_RECORD)
                index += 1
                yield Packet(index, 0.0, wirelen, linktype, body[4 : 4 + caplen])
            # name resolution, statistics, decryption secrets, custom and unknown blocks carry no packet: skipped

    @staticmethod
    def _block_length(raw: bytes, order: str) -> int:
        total = int(struct.unpack(order + "I", raw)[0])
        if total < 12 or total % 4 or total > MAX_BLOCK:
            raise CaptureError(f"pcapng block with an impossible length ({total})")
        return total

    @staticmethod
    def _interface(body: bytes, order: str) -> tuple[int, float, int]:
        if len(body) < 8:
            raise CaptureError("pcapng interface block is too short")
        linktype, _res, snaplen = struct.unpack(order + "HHI", body[:8])
        tick = 1e-6
        pos = 8
        while pos + 4 <= len(body):
            code, length = struct.unpack(order + "HH", body[pos : pos + 4])
            if code == 0:
                break
            value = body[pos + 4 : pos + 4 + length]
            if code == 9 and len(value) == 1:  # if_tsresol
                v = value[0]
                tick = 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -(v & 0x7F)
            pos += 4 + ((length + 3) & ~3)
        return linktype, tick, snaplen
