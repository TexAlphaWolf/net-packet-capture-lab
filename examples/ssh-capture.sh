#!/usr/bin/env bash
# Capture on a remote Linux host (needs tcpdump there and permission to run it) and read it here, without writing the
# capture to the remote disk. Take captures only on networks you are allowed to observe.
#   ./ssh-capture.sh user@host eth0 60
set -euo pipefail
HOST="${1:?user@host}"; IFACE="${2:-any}"; SECONDS_TO_RUN="${3:-60}"
# -s 0: whole packets; -U: do not buffer; the capture comes back on standard input of pcaplab
ssh "$HOST" "sudo timeout $SECONDS_TO_RUN tcpdump -i $IFACE -s 0 -U -w - not port 22" | pcaplab summary -
