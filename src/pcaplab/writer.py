"""Writing a classic pcap file packet by packet (used by the ``filter`` command)."""

from __future__ import annotations

import struct
from pathlib import Path
from types import TracebackType
from typing import BinaryIO

from .model import Packet


class PcapWriter:
    def __init__(self, path: str | Path, linktype: int, snaplen: int = 262144) -> None:
        self._f: BinaryIO = open(path, "wb")  # noqa: SIM115 (closed in close)
        self._f.write(struct.pack("<IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, snaplen, linktype))  # nanosecond resolution
        self.count = 0

    def write(self, pkt: Packet) -> None:
        sec = int(pkt.ts)
        nsec = min(999_999_999, round((pkt.ts - sec) * 1e9))
        self._f.write(struct.pack("<IIII", sec, nsec, len(pkt.data), pkt.wirelen) + pkt.data)
        self.count += 1

    def close(self) -> None:
        self._f.close()

    def __enter__(self) -> PcapWriter:
        return self

    def __exit__(self, *exc: type[BaseException] | BaseException | TracebackType | None) -> None:
        self.close()
