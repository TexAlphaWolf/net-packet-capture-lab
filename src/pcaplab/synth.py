"""Builds captures whose content is known exactly: packet builders, pcap and pcapng writers, and a traffic generator
that mixes ordinary use of a small network with scans, DNS tunnels, beacons, ARP spoofing and clear-text logins.

The generator returns the list of what it injected (the truth) next to the frames, so the detectors can be scored.
Everything is documentation address space (RFC 5737) and locally administered MAC addresses."""

from __future__ import annotations

import base64
import random
import socket
import struct
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

T0 = 1_760_000_000.0
LAN = "10.0.0."
GATEWAY = "10.0.0.1"
RESOLVER = "10.0.0.2"
Frame = tuple[float, bytes]


def mac_of(ip: str) -> bytes:
    return b"\x02\x00" + socket.inet_aton(ip)


GW_MAC = mac_of(GATEWAY)


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return int(~total & 0xFFFF)


def _pseudo(src: str, dst: str, proto: int, length: int) -> bytes:
    if ":" in src:
        return (
            socket.inet_pton(socket.AF_INET6, src)
            + socket.inet_pton(socket.AF_INET6, dst)
            + struct.pack("!IxxxB", length, proto)
        )
    return socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!xBH", proto, length)


def tcp(
    src: str, dst: str, sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes = b"", win: int = 64240
) -> bytes:
    head = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, 5 << 4, flags, win, 0, 0)
    seg = head + payload
    csum = checksum(_pseudo(src, dst, 6, len(seg)) + seg)
    return seg[:16] + struct.pack("!H", csum) + seg[18:]


def udp(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    seg = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    csum = checksum(_pseudo(src, dst, 17, len(seg)) + seg) or 0xFFFF
    return seg[:6] + struct.pack("!H", csum) + seg[8:]


def icmp_echo(ident: int, seq: int, reply: bool = False) -> bytes:
    body = struct.pack("!BBHHH", 0 if reply else 8, 0, 0, ident, seq) + b"pcaplab-ping-0123456789abcdef"
    return body[:2] + struct.pack("!H", checksum(body)) + body[4:]


def ipv4(src: str, dst: str, proto: int, payload: bytes, ttl: int = 64, ident: int = 0, frag: int = 0) -> bytes:
    head = (
        struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(payload), ident, frag, ttl, proto, 0)
        + socket.inet_aton(src)
        + socket.inet_aton(dst)
    )
    return head[:10] + struct.pack("!H", checksum(head)) + head[12:] + payload


def ipv6(src: str, dst: str, nxt: int, payload: bytes, hop: int = 64) -> bytes:
    head = struct.pack("!IHBB", 6 << 28, len(payload), nxt, hop)
    return head + socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst) + payload


def ether(dst: bytes, src: bytes, etype: int, payload: bytes, vlan: int | None = None) -> bytes:
    tag = struct.pack("!HH", 0x8100, vlan) if vlan is not None else b""
    frame = dst + src + tag + struct.pack("!H", etype) + payload
    return frame + b"\x00" * max(0, 60 - len(frame))  # the shortest frame on the wire is 60 bytes (before the FCS)


def arp(op: int, sha: bytes, spa: str, tha: bytes, tpa: str) -> bytes:
    return struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) + sha + socket.inet_aton(spa) + tha + socket.inet_aton(tpa)


def _qname(name: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"


def dns_message(
    ident: int,
    name: str,
    qtype: int,
    *,
    response: bool = False,
    rcode: int = 0,
    answers: Iterable[tuple[int, bytes]] = (),
) -> bytes:
    answers = list(answers)
    flags = (0x8180 | rcode) if response else 0x0100
    out = struct.pack("!HHHHHH", ident, flags, 1, len(answers), 0, 0) + _qname(name) + struct.pack("!HH", qtype, 1)
    for rtype, rdata in answers:
        out += b"\xc0\x0c" + struct.pack("!HHIH", rtype, 1, 60, len(rdata)) + rdata
    return out


def tls_client_hello(sni: str, rng: random.Random) -> bytes:
    name = sni.encode()
    sn = struct.pack("!HBH", len(name) + 3, 0, len(name)) + name
    exts = struct.pack("!HH", 0, len(sn)) + sn + struct.pack("!HHH", 43, 3, 2) + b"\x03\x04"
    body = (
        b"\x03\x03"
        + rng.randbytes(32)
        + b"\x00"
        + struct.pack("!H", 4)
        + b"\x13\x01\x13\x02"
        + b"\x01\x00"
        + struct.pack("!H", len(exts))
        + exts
    )
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


# files ----------------------------------------------------------------------------------------------------------


def pcap_bytes(
    frames: Iterable[Frame], *, nano: bool = False, big: bool = False, linktype: int = 1, snaplen: int = 262144
) -> bytes:
    o = ">" if big else "<"
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    out = [struct.pack(o + "IHHiIII", magic, 2, 4, 0, 0, snaplen, linktype)]
    for ts, data in frames:
        sec = int(ts)
        frac = round((ts - sec) * (1e9 if nano else 1e6))
        if frac >= (1e9 if nano else 1e6):
            sec, frac = sec + 1, 0
        out.append(struct.pack(o + "IIII", sec, frac, len(data), len(data)) + data)
    return b"".join(out)


def _block(o: str, btype: int, body: bytes) -> bytes:
    body += b"\x00" * (-len(body) % 4)
    total = len(body) + 12
    return struct.pack(o + "II", btype, total) + body + struct.pack(o + "I", total)


def pcapng_bytes(frames: Iterable[Frame], *, big: bool = False, linktype: int = 1, tsresol: int = 6) -> bytes:
    o = ">" if big else "<"
    out = [_block(o, 0x0A0D0D0A, struct.pack(o + "IHHq", 0x1A2B3C4D, 1, 0, -1))]
    opt = struct.pack(o + "HH", 9, 1) + bytes([tsresol]) + b"\x00\x00\x00" + struct.pack(o + "HH", 0, 0)
    out.append(_block(o, 1, struct.pack(o + "HHI", linktype, 0, 262144) + opt))
    scale = 10**tsresol
    for ts, data in frames:
        ticks = round(ts * scale)
        body = struct.pack(o + "IIIII", 0, ticks >> 32, ticks & 0xFFFFFFFF, len(data), len(data)) + data
        out.append(_block(o, 6, body))
    return b"".join(out)


def write_capture(path: str | Path, frames: Iterable[Frame], fmt: str = "pcap") -> None:
    data = pcapng_bytes(frames) if fmt == "pcapng" else pcap_bytes(frames)
    Path(path).write_bytes(data)


# traffic ---------------------------------------------------------------------------------------------------------


@dataclass
class Truth:
    """One thing the generator put in the capture on purpose."""

    kind: str  # port-scan, dns-tunnel, nxdomain-storm, beacon, arp-conflict, cleartext-credentials, tcp-retransmissions
    host: str  # the source (the scanner, the client, the caller, the IP whose owner changes)
    info: dict[str, object] = field(default_factory=dict)
    detectable: bool = True  # False: below the thresholds on purpose (a slow scan), so a miss is expected


class Traffic:
    def __init__(self, seed: int = 1, start: float = T0) -> None:
        self.rng = random.Random(seed)
        self.start = start
        self.frames: list[Frame] = []
        self.truth: list[Truth] = []
        self._port = 40000
        self._id = 1

    # basics

    def _l2(self, src: str, dst: str) -> tuple[bytes, bytes]:
        def mac(ip: str) -> bytes:
            return mac_of(ip) if ip.startswith(LAN) else GW_MAC

        return mac(dst), mac(src)

    def ip_frame(self, t: float, src: str, dst: str, proto: int, payload: bytes, ttl: int = 64) -> None:
        self._id = (self._id + 1) & 0xFFFF
        d, s = self._l2(src, dst)
        self.frames.append((t, ether(d, s, 0x0800, ipv4(src, dst, proto, payload, ttl, self._id))))

    def eph(self) -> int:
        self._port = 40000 + (self._port - 40000 + self.rng.randint(1, 37)) % 20000
        return self._port

    def tcp_frame(
        self, t: float, src: str, dst: str, sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes = b""
    ) -> None:
        self.ip_frame(t, src, dst, 6, tcp(src, dst, sport, dport, seq, ack, flags, payload))

    def udp_frame(self, t: float, src: str, dst: str, sport: int, dport: int, payload: bytes) -> None:
        self.ip_frame(t, src, dst, 17, udp(src, dst, sport, dport, payload))

    def tcp_session(
        self,
        t: float,
        client: str,
        server: str,
        dport: int,
        *,
        up: Iterable[bytes] = (b"",),
        down: Iterable[bytes] = (b"",),
        rtt: float = 0.02,
        sport: int | None = None,
        close: str = "fin",
        loss: float = 0.0,
    ) -> float:
        """A whole TCP conversation. ``loss`` is the chance that a data segment is sent twice. Returns the end time."""
        r = self.rng
        sport = sport or self.eph()
        cs, ss = r.randrange(1 << 32), r.randrange(1 << 32)
        self.tcp_frame(t, client, server, sport, dport, cs, 0, 0x02)
        t += rtt
        self.tcp_frame(t, server, client, dport, sport, ss, cs + 1, 0x12)
        t += rtt / 10
        cs, ss = cs + 1, ss + 1
        self.tcp_frame(t, client, server, sport, dport, cs, ss, 0x10)

        def send(t: float, a: str, b: str, pa: int, pb: int, seq: int, ack: int, data: bytes) -> tuple[float, int]:
            for i in range(0, len(data), 1400):
                chunk = data[i : i + 1400]
                self.tcp_frame(t, a, b, pa, pb, seq, ack, 0x18, chunk)
                if loss and r.random() < loss:
                    self.tcp_frame(t + 0.2, a, b, pa, pb, seq, ack, 0x18, chunk)  # the same segment again
                seq += len(chunk)
                t += 0.0005
            return t, seq

        for u, d in zip(up, down, strict=False):
            if u:
                t, cs = send(t + rtt, client, server, sport, dport, cs, ss, u)
                self.tcp_frame(t + rtt / 2, server, client, dport, sport, ss, cs, 0x10)
            if d:
                t, ss = send(t + rtt, server, client, dport, sport, ss, cs, d)
                self.tcp_frame(t + rtt / 2, client, server, sport, dport, cs, ss, 0x10)
        t += rtt
        if close == "fin":
            self.tcp_frame(t, client, server, sport, dport, cs, ss, 0x11)
            self.tcp_frame(t + rtt, server, client, dport, sport, ss, cs + 1, 0x11)
            self.tcp_frame(t + 1.5 * rtt, client, server, sport, dport, cs + 1, ss + 1, 0x10)
        elif close == "rst":
            self.tcp_frame(t, client, server, sport, dport, cs, ss, 0x14)
        return t + 2 * rtt

    def dns_lookup(
        self,
        t: float,
        client: str,
        name: str,
        qtype: int = 1,
        *,
        rcode: int = 0,
        resolver: str = RESOLVER,
        answer: bytes | None = None,
    ) -> None:
        ident = self.rng.randrange(1 << 16)
        sport = self.eph()
        self.udp_frame(t, client, resolver, sport, 53, dns_message(ident, name, qtype))
        if answer is None and rcode == 0:
            answer = socket.inet_aton(f"198.51.100.{self.rng.randint(2, 250)}") if qtype == 1 else b""
        answers = [(qtype, answer)] if rcode == 0 and answer is not None else []
        self.udp_frame(
            t + 0.012,
            resolver,
            client,
            53,
            sport,
            dns_message(ident, name, qtype, response=True, rcode=rcode, answers=answers),
        )

    # the ordinary use of a small network

    SITES = (
        "www.example.com",
        "api.example.org",
        "cdn.example.net",
        "mail.example.com",
        "files.example.org",
        "news.example.net",
        "video.example.com",
        "shop.example.org",
    )

    def background(self, duration: float, clients: int = 12) -> None:
        r = self.rng
        sites = {s: f"198.51.100.{10 + i}" for i, s in enumerate(self.SITES)}
        for c in range(clients):
            ip = f"{LAN}{10 + c}"
            t = self.start + r.uniform(0, 20)
            while t < self.start + duration:
                site = r.choice(self.SITES)
                self.dns_lookup(t, ip, site, answer=socket.inet_aton(sites[site]))
                t += 0.05
                size = int(r.lognormvariate(9, 1.2))
                if r.random() < 0.8:
                    t = self.tcp_session(
                        t,
                        ip,
                        sites[site],
                        443,
                        up=[tls_client_hello(site, r), r.randbytes(200)],
                        down=[r.randbytes(1200), b"\x17\x03\x03" + r.randbytes(min(size, 20000))],
                    )
                else:
                    req = f"GET /index.html HTTP/1.1\r\nHost: {site}\r\nUser-Agent: lab\r\n\r\n".encode()
                    t = self.tcp_session(
                        t,
                        ip,
                        sites[site],
                        80,
                        up=[req],
                        down=[b"HTTP/1.1 200 OK\r\nContent-Length: 4000\r\n\r\n" + b"x" * min(size, 20000)],
                    )
                t += r.expovariate(1 / 12)
            # NTP every 64 seconds: regular on purpose, and harmless
            nt = self.start + r.uniform(0, 64)
            while nt < self.start + duration:
                sport = self.eph()
                self.udp_frame(nt, ip, "203.0.113.123", sport, 123, r.randbytes(48))
                self.udp_frame(nt + 0.03, "203.0.113.123", ip, 123, sport, r.randbytes(48))
                nt += 64
        # the gateway tells its address now and then; a ping to it
        for k in range(int(duration // 120)):
            who = f"{LAN}{10 + k % clients}"
            self.frames.append(
                (
                    self.start + 30 + 120 * k,
                    ether(mac_of(who), GW_MAC, 0x0806, arp(2, GW_MAC, GATEWAY, mac_of(who), who)),
                )
            )
        for k in range(int(duration // 90)):
            who = f"{LAN}{10 + k % clients}"
            t = self.start + 40 + 90 * k
            self.ip_frame(t, who, GATEWAY, 1, icmp_echo(k, 1))
            self.ip_frame(t + 0.001, GATEWAY, who, 1, icmp_echo(k, 1, True))

    # hard negatives: busy but harmless

    def harmless_oddities(self, duration: float) -> None:
        r = self.rng
        # a client that opens ten ports of a server in a second (below the scan threshold)
        t = self.start + duration * 0.3
        for port in range(8000, 8010):
            t = self.tcp_session(t, f"{LAN}30", f"{LAN}8", port, up=[b"hello"], down=[b"world"]) + 0.01
        # a CDN: many short, hex-like names
        for i in range(40):
            self.dns_lookup(self.start + 100 + i * 7, f"{LAN}32", f"e{r.randrange(16**8):08x}.cdn.example.net")
        # a few typos
        for i in range(6):
            self.dns_lookup(self.start + 200 + i * 40, f"{LAN}33", f"wwww{i}.example.com", rcode=3)
        # a monitor that checks twelve service ports of the DNS server in a few seconds, every five minutes: connections
        # that carry no data, like a scan, but twelve is fewer than the fifteen the scan rule needs
        for round_ in range(int(duration // 300)):
            t = self.start + 20 + 300 * round_
            for k, port in enumerate((22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306)):
                self.tcp_session(t + 0.2 * k, f"{LAN}35", RESOLVER, port)
        # polling with a random pause: nothing regular in it
        t = self.start + 50
        while t < self.start + duration:
            t = self.tcp_session(t, f"{LAN}34", "198.51.100.30", 443, up=[b"poll"], down=[b"ok"]) + r.uniform(8, 90)

    # attacks ---------------------------------------------------------------------------------------------------------

    def syn_scan(
        self,
        scanner: str,
        targets: list[str],
        ports: list[int],
        t: float,
        rate: float,
        open_ports: set[tuple[str, int]] | None = None,
        *,
        drop: bool = False,
        mode: str = "syn",
    ) -> None:
        """One probe per (target, port), ``rate`` probes a second. Closed ports answer RST (or nothing if ``drop``);
        open ones answer SYN-ACK and, in ``syn`` mode, get a RST; in ``connect`` mode the handshake is completed."""
        r = self.rng
        open_ports = open_ports or set()
        for host in targets:
            for port in ports:
                sport = self.eph()
                seq = r.randrange(1 << 32)
                self.tcp_frame(t, scanner, host, sport, port, seq, 0, 0x02)
                if (host, port) in open_ports:
                    sa = r.randrange(1 << 32)
                    self.tcp_frame(t + 0.001, host, scanner, port, sport, sa, seq + 1, 0x12)
                    if mode == "connect":
                        self.tcp_frame(t + 0.002, scanner, host, sport, port, seq + 1, sa + 1, 0x10)
                        self.tcp_frame(t + 0.003, scanner, host, sport, port, seq + 1, sa + 1, 0x14)
                    else:
                        self.tcp_frame(t + 0.002, scanner, host, sport, port, seq + 1, 0, 0x04)
                elif not drop:
                    self.tcp_frame(t + 0.001, host, scanner, port, sport, 0, seq + 1, 0x14)
                t += 1 / rate

    def dns_tunnel(self, client: str, domain: str, t: float, n: int, gap: float = 0.4) -> None:
        r = self.rng
        for i in range(n):
            payload = base64.b32encode(r.randbytes(r.randint(26, 34))).decode().rstrip("=").lower()
            name = f"{payload[:30]}.{payload[30:]}.{domain}" if len(payload) > 30 else f"{payload}.{domain}"
            qtype = 16 if i % 3 else 10
            ident = r.randrange(1 << 16)
            sport = self.eph()
            self.udp_frame(t, client, RESOLVER, sport, 53, dns_message(ident, name, qtype))
            txt = bytes([20]) + r.randbytes(20)
            self.udp_frame(
                t + 0.03,
                RESOLVER,
                client,
                53,
                sport,
                dns_message(ident, name, qtype, response=True, answers=[(qtype, txt)]),
            )
            t += gap * r.uniform(0.5, 1.5)

    def dga(self, client: str, t: float, n: int, gap: float = 3.0) -> None:
        r = self.rng
        for _ in range(n):
            name = "".join(r.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(r.randint(10, 16))) + r.choice(
                [".com", ".net", ".org", ".info"]
            )
            self.dns_lookup(t, client, name, rcode=3)
            t += gap * r.uniform(0.5, 1.5)

    def beacon(
        self,
        src: str,
        dst: str,
        port: int,
        t: float,
        interval: float,
        n: int,
        jitter: float = 0.08,
        *,
        tls: bool = True,
    ) -> None:
        r = self.rng
        for _ in range(n):
            if tls:
                self.tcp_session(
                    t,
                    src,
                    dst,
                    port,
                    up=[tls_client_hello("updates.example.net", r), r.randbytes(60)],
                    down=[b"\x17\x03\x03" + r.randbytes(40)],
                )
            else:
                self.tcp_session(
                    t,
                    src,
                    dst,
                    port,
                    up=[b"GET /check HTTP/1.1\r\nHost: c2.example.net\r\n\r\n"],
                    down=[b"HTTP/1.1 204 No Content\r\n\r\n"],
                )
            t += interval * (1 + r.uniform(-jitter, jitter))

    def arp_spoof(self, victim_ip: str, attacker_ip: str, t: float, rounds: int = 6) -> None:
        legit, evil = GW_MAC, mac_of(attacker_ip)
        who = f"{LAN}12"
        for k in range(rounds):
            self.frames.append(
                (t + k * 10, ether(mac_of(who), legit, 0x0806, arp(2, legit, victim_ip, mac_of(who), who)))
            )
            self.frames.append(
                (t + k * 10 + 3, ether(mac_of(who), evil, 0x0806, arp(2, evil, victim_ip, mac_of(who), who)))
            )

    def http_basic(self, t: float, client: str, server: str, port: int, user: str, password: str) -> None:
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        req = f"GET /admin HTTP/1.1\r\nHost: {server}\r\nAuthorization: Basic {token}\r\n\r\n".encode()
        self.tcp_session(t, client, server, port, up=[req], down=[b"HTTP/1.1 200 OK\r\n\r\nwelcome"])

    def ftp_login(self, t: float, client: str, server: str, user: str, password: str) -> None:
        self.tcp_session(
            t,
            client,
            server,
            21,
            up=[b"", f"USER {user}\r\n".encode(), f"PASS {password}\r\n".encode()],
            down=[b"220 ready\r\n", b"331 password?\r\n", b"230 ok\r\n"],
        )

    def lossy_upload(self, t: float, client: str, server: str, size: int, loss: float) -> None:
        self.tcp_session(
            t, client, server, 443, up=[self.rng.randbytes(size)], down=[b"\x17\x03\x03ok"], rtt=0.05, loss=loss
        )

    def output(self) -> list[Frame]:
        return sorted(self.frames, key=lambda f: f[0])


def build_scenario(
    seed: int = 1, duration: float = 1800.0, *, attacks: bool = True, oddities: bool = True
) -> tuple[list[Frame], list[Truth]]:
    """A capture of ``duration`` seconds on a small network, with the attacks above at random places and sizes."""
    tr = Traffic(seed)
    r = tr.rng
    tr.background(duration)
    if oddities:
        tr.harmless_oddities(duration)
    if attacks:
        lan_hosts = [f"{LAN}{n}" for n in range(1, 255)]

        def t(lo: float, hi: float) -> float:
            return tr.start + duration * r.uniform(lo, hi)

        # scans: one vertical, one horizontal, one by connecting
        ports = r.sample(range(1, 1025), r.randint(150, 400))
        tr.syn_scan(
            "203.0.113.50",
            [f"{LAN}5"],
            ports,
            t(0.05, 0.15),
            50,
            {(f"{LAN}5", 22), (f"{LAN}5", 80)} & {(f"{LAN}5", p) for p in ports} | {(f"{LAN}5", ports[0])},
        )
        tr.truth.append(Truth("port-scan", "203.0.113.50", {"shape": "vertical", "ports": len(ports)}))
        hosts = r.sample(lan_hosts, r.randint(60, 150))
        tr.syn_scan(f"{LAN}77", hosts, [445], t(0.2, 0.3), 30, drop=True)
        tr.truth.append(Truth("port-scan", f"{LAN}77", {"shape": "horizontal", "hosts": len(hosts)}))
        cports = list(range(1000, 1000 + r.randint(25, 60)))
        tr.syn_scan("198.51.100.99", [f"{LAN}5"], cports, t(0.35, 0.4), 20, {(f"{LAN}5", cports[3])}, mode="connect")
        tr.truth.append(Truth("port-scan", "198.51.100.99", {"shape": "connect", "ports": len(cports)}))
        # a scan too slow for the rule (one probe every 20 s): a miss is expected
        tr.syn_scan("203.0.113.60", [f"{LAN}5"], list(range(2000, 2020)), t(0.4, 0.5), 0.05)
        tr.truth.append(Truth("port-scan", "203.0.113.60", {"shape": "slow", "ports": 20}, detectable=False))

        client = f"{LAN}23"
        n_tunnel = r.randint(60, 200)
        tr.dns_tunnel(client, "t.badcdn-example.org", t(0.1, 0.5), n_tunnel)
        tr.truth.append(Truth("dns-tunnel", client, {"queries": n_tunnel}))
        n_dga = r.randint(30, 80)
        tr.dga(f"{LAN}31", t(0.1, 0.5), n_dga)
        tr.truth.append(Truth("nxdomain-storm", f"{LAN}31", {"names": n_dga}))

        interval = r.choice([30.0, 45.0, 60.0, 120.0])
        n = max(10, min(int((duration * 0.8) / interval), 60))
        tr.beacon(f"{LAN}45", "192.0.2.77", 443, tr.start + r.uniform(5, 100), interval, n, r.uniform(0.02, 0.1))
        tr.truth.append(Truth("beacon", f"{LAN}45", {"interval": interval, "count": n, "dst": "192.0.2.77"}))
        tr.beacon(f"{LAN}46", "192.0.2.88", 8080, tr.start + r.uniform(5, 100), 30.0, 40, 0.05, tls=False)
        tr.truth.append(Truth("beacon", f"{LAN}46", {"interval": 30.0, "count": 40, "dst": "192.0.2.88"}))

        tr.arp_spoof(GATEWAY, f"{LAN}66", t(0.5, 0.7), 6)
        tr.truth.append(Truth("arp-conflict", GATEWAY, {"attacker": f"{LAN}66"}))
        tr.http_basic(t(0.1, 0.9), f"{LAN}12", f"{LAN}8", 8080, "admin", "S3cret!pw")
        tr.truth.append(Truth("cleartext-credentials", f"{LAN}12", {"kind": "http-basic"}))
        tr.ftp_login(t(0.1, 0.9), f"{LAN}14", f"{LAN}9", "backup", "hunter2")
        tr.truth.append(Truth("cleartext-credentials", f"{LAN}14", {"kind": "ftp"}))
        tr.lossy_upload(t(0.1, 0.8), f"{LAN}19", "198.51.100.20", 600_000, r.uniform(0.1, 0.25))
        tr.truth.append(Truth("tcp-retransmissions", f"{LAN}19"))
    return tr.output(), tr.truth
