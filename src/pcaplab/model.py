"""Shared small pieces: the packet read from a file, errors, and number formatting."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

# link types this tool decodes (the numbers of libpcap)
LINK_NULL = 0  # BSD loopback: a 4-byte address family, then IP (macOS and Windows loopback captures)
LINK_ETHERNET = 1
LINK_RAW = 101
LINK_LOOP = 108  # OpenBSD loopback: the same, in network byte order
LINK_LINUX_SLL = 113
LINK_IPV4 = 228
LINK_IPV6 = 229
LINK_LINUX_SLL2 = 276  # what current tcpdump writes for "-i any"
LINK_TYPES = {
    LINK_NULL: "BSD loopback",
    LINK_LOOP: "OpenBSD loopback",
    LINK_LINUX_SLL2: "linux cooked v2",
    LINK_ETHERNET: "ethernet",
    LINK_RAW: "raw IP",
    LINK_LINUX_SLL: "linux cooked",
    LINK_IPV4: "IPv4",
    LINK_IPV6: "IPv6",
}

# names for the ports people know; only used to label traffic, never to decide anything
SERVICES = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp",
    68: "dhcp",
    80: "http",
    110: "pop3",
    123: "ntp",
    137: "netbios",
    138: "netbios",
    143: "imap",
    161: "snmp",
    389: "ldap",
    443: "https",
    445: "smb",
    514: "syslog",
    587: "submission",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1883: "mqtt",
    1900: "ssdp",
    3306: "mysql",
    3389: "rdp",
    5353: "mdns",
    5432: "postgres",
    8080: "http-alt",
    8443: "https-alt",
}


class CaptureError(ValueError):
    """The file is not a capture this tool can read."""


@dataclass(frozen=True, slots=True)
class Packet:
    """One record of a capture file, before any decoding."""

    index: int  # 1-based position in the file
    ts: float  # seconds since the epoch (UTC)
    wirelen: int  # length on the wire
    linktype: int
    data: bytes  # what was captured (may be shorter than wirelen)


def fmt_time(ts: float, *, ms: bool = False) -> str:
    dt = datetime.fromtimestamp(ts, UTC)
    return dt.strftime("%Y-%m-%d %H:%M:%S") + (f".{dt.microsecond // 1000:03d}" if ms else "") + "Z"


def fmt_bytes(n: float) -> str:
    if n < 1024:
        return f"{int(n)} B"
    value = float(n)
    for unit in ("KiB", "MiB", "GiB", "TiB"):
        value /= 1024
        if value < 1024 or unit == "TiB":
            return f"{value:.1f} {unit}"
    return f"{value:.1f} TiB"  # pragma: no cover


def fmt_dur(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    if seconds < 60:
        return f"{seconds:.1f} s"
    minutes, sec = divmod(int(seconds + 0.5), 60)
    if minutes < 60:
        return f"{minutes} min {sec} s"
    hours, minutes = divmod(minutes, 60)
    if hours < 48:
        return f"{hours} h {minutes} min"
    days, hours = divmod(hours, 24)
    return f"{days} d {hours} h"


def fmt_pct(part: float, whole: float) -> str:
    return f"{100 * part / whole:.1f}%" if whole else "0.0%"
