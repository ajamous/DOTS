#!/bin/sh
# Userspace-only rtpengine (no kernel module in containers), ng control on 2223.
set -eu
IP=$(hostname -i | awk '{print $1}')
exec rtpengine --foreground --log-stderr --table=-1 \
  --interface="$IP" --listen-ng="$IP:2223" \
  --port-min="${RTP_PORT_MIN:-30000}" --port-max="${RTP_PORT_MAX:-30999}" \
  --log-level="${RTP_LOG_LEVEL:-5}" --delete-delay=0
