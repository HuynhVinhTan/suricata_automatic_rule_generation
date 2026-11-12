#!/usr/bin/env bash
set -euo pipefail
ROOT=/home/kali/suricata-ai-showcase
OUT=${1:-$ROOT/evidence/session-$(date -u +%Y%m%dT%H%M%SZ).pcap}
if ! getcap "$(command -v tcpdump)" 2>/dev/null | grep -q cap_net_raw; then
  echo 'CAPTURE_BLOCKED: tcpdump lacks cap_net_raw; owner must authorize an existing approved capture method.' >&2
  exit 77
fi
mkdir -p "$(dirname "$OUT")"
exec tcpdump -i eth1 -s 65535 -n -w "$OUT" 'host 192.168.10.10 and host 192.168.10.20'
