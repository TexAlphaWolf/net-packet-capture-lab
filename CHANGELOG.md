# Changelog

## 1.0.0

First release.

- Reads pcap (both byte orders, microsecond and nanosecond) and pcapng, as a stream, from a file or standard input.
- Decodes Ethernet (VLAN tags), Linux cooked, raw IP, ARP, IPv4, IPv6 (extension headers), TCP, UDP, ICMP, DNS, HTTP/1.x
  and the server name of a TLS ClientHello.
- Flows with the TCP handshake, resets, retransmissions and round-trip time.
- Detectors: port scans, DNS tunnels, floods of names that do not exist, beacons, ARP conflicts, clear-text passwords,
  TCP retransmissions. Every finding carries the numbers behind it.
- A filter language (`tcp and port 443`, `host 10.0.0.5 and not dns`, ...), used by every command and by `filter`.
- Reports as text, Markdown, JSON and one self-contained HTML page; `--anonymize`.
- `sample`: synthetic captures with scans, tunnels, beacons and so on injected at known places, for tests and demos.
