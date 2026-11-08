# Security

## Model

pcaplab is a command line program that **reads files and writes files**. It opens no network connection, runs no other
program and starts no service. A capture is untrusted input (it may come from a hostile network), so the reader and
the decoder are written to survive anything in it.

- **Nothing in a capture can crash or hang the decoder.** Every header is length-checked; a packet that cannot be
  read comes back with an error text and is counted, never raised. DNS names follow compression pointers at most 32
  times and are limited to 255 bytes; extension headers, tags and options are bounded. `tests/test_decode.py` decodes
  every prefix of every reference packet, thousands of randomly damaged packets and random bytes on every link type.
- **File limits**: a record longer than 16 MiB or a pcapng block longer than 128 MiB is refused as a damaged file.
  A file cut off in its last record is read up to there, with a warning. The capture is read as a stream; memory grows
  with the number of flows and distinct names, not with the file size, and the tables that depend on what the network
  sends are capped (flows, names per client and domain, ARP changes per address).
- **Text from the network is cleaned** before it is kept: names, host names, user names and URLs contain only printable
  ASCII, so a hostile name cannot inject terminal control sequences into the output.
- **Secrets are never kept.** For HTTP Basic the user name is kept and the password is dropped when the header is
  parsed; for FTP only the fact that `PASS` was sent. HTTP query strings are cut off (they often carry tokens). No
  finding, report or JSON holds a password; `tests/` and the Docker end-to-end check this on the real output.
- **The HTML report has no script and no external file**, a `default-src 'none'` policy, and everything that came from
  the network is escaped (tested with names such as `<script>`).
- **`--anonymize`** replaces IP addresses, MAC addresses and the names seen in the capture with keyed labels (HMAC with a
  random key, different on every run), so a report can be published. See the limits below.
- The Docker image runs as an unprivileged user and works with a read-only root filesystem, no capabilities and
  `--network none`.

What it does not protect:

- **`--anonymize` works on the text of the report.** It knows the addresses and names the analysis saw. A name that
  appears only inside a payload it did not decode, a host name in a user name, or a finding's free text from another
  source is not covered. Read an anonymised report before publishing it, and keep the capture itself private: a pcap
  holds everything that crossed the wire, including secrets in protocols this tool does not parse.
- The detectors report patterns, not intent: a finding is a reason to look, not proof (see
  [limitations](docs/limitations.md)).

## Reporting

Please report vulnerabilities privately through GitHub's "Report a vulnerability" (Security tab), not in a public issue.
