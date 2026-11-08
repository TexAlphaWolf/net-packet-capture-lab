#!/usr/bin/env bash
# End to end inside the image (read-only root, no capabilities, no network): a synthetic capture is written to a
# volume, analysed, turned into a report and filtered, and the output is checked. Needs Docker.
# Usage: tools/docker_e2e.sh [image]
set -euo pipefail
IMAGE="${1:-pcaplab}"
ID="$$"
VOL="pcaplab-e2e-$ID"
TMP="$(mktemp -d)"
trap 'docker volume rm -f "$VOL" >/dev/null 2>&1 || true; rm -rf "$TMP"' EXIT

[ "$(docker run --rm --entrypoint id "$IMAGE" -u)" != 0 ]   # not root
docker volume create "$VOL" >/dev/null
docker run --rm --user 0 -v "$VOL":/data --entrypoint chown "$IMAGE" 10001 /data

RUN=(docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges --network none -v "$VOL":/data "$IMAGE")
# the output of a command is kept in $out, so that a pipe closing early cannot hide or fake a result
out="$("${RUN[@]}" sample -o demo.pcap --duration 600 --truth truth.json)"
echo "$out" >&2
grep -q 'things injected' <<<"$out"

set +e; out="$("${RUN[@]}" findings demo.pcap)"; rc=$?; set -e      # exit code 1: there are findings
echo "$out" >&2
[ "$rc" = 1 ]
for want in 'TCP port scan from 203.0.113.50' 'Possible DNS tunnel' 'HTTP Basic login' 'FTP password' 'claimed by' 'Regular connections'; do
  grep -q "$want" <<<"$out"
done
! grep -q -e 'S3cret' -e 'hunter2' <<<"$out"                          # the secrets are never kept

out="$("${RUN[@]}" summary demo.pcap)"
grep -q 'Top hosts by bytes' <<<"$out"
grep -q 'TLS server names' <<<"$out"
out="$("${RUN[@]}" flows demo.pcap --top 3)"
[ "$(wc -l <<<"$out")" -eq 4 ]

"${RUN[@]}" report demo.pcap -o out/report.html >/dev/null
docker run --rm --entrypoint cat -v "$VOL":/data "$IMAGE" /data/out/report.html > "$TMP/report.html"
grep -q "default-src 'none'" "$TMP/report.html"
! grep -qi '<script' "$TMP/report.html"
! grep -q -e 'S3cret' -e 'hunter2' "$TMP/report.html"

out="$("${RUN[@]}" findings demo.pcap --anonymize)" || true
! grep -q -e '203.0.113.50' -e '10.0.0.23' <<<"$out"                  # addresses are replaced when asked

"${RUN[@]}" filter demo.pcap 'dns and host 10.0.0.23' -o dns.pcap >/dev/null
set +e; out="$("${RUN[@]}" findings dns.pcap)"; set -e
grep -q 'Possible DNS tunnel' <<<"$out"                                # the tunnel is still there, the rest is gone
! grep -q 'port scan' <<<"$out"

# a capture can also come on standard input
out="$(docker run --rm --entrypoint cat -v "$VOL":/data "$IMAGE" /data/demo.pcap | docker run --rm -i --read-only --cap-drop ALL --network none "$IMAGE" summary -)"
grep -q 'Top hosts by bytes' <<<"$out"

set +e; "${RUN[@]}" summary nope.pcap >/dev/null 2>&1; rc=$?; set -e   # a missing file is exit code 2
[ "$rc" = 2 ]
echo "docker end-to-end: OK"
