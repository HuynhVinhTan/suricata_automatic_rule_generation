#!/usr/bin/env bash
set -euo pipefail

# Owner-invoked VM2-only workflow. It never changes capabilities, sudoers,
# firewall, Suricata, Filebeat, EVE, or ELK configuration.
ROOT=/home/kali/suricata-ai-showcase
IFACE=eth1
SOURCE_IP=192.168.10.20
TARGET_IP=192.168.10.10
MAX_SECONDS=120
MAX_PACKETS=5000
SNAPLEN=96
OUT=${1:-$ROOT/evidence/attack-$(date -u +%Y%m%dT%H%M%SZ).pcap}
MANIFEST=${2:-$ROOT/evidence/$(basename "${OUT%.pcap}").json}

if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
  echo 'CAPTURE_BLOCKED: invoke as the owner user; only tcpdump may prompt through sudo.' >&2
  exit 77
fi
command -v ip >/dev/null || { echo 'CAPTURE_BLOCKED: ip command is unavailable.' >&2; exit 77; }
command -v tcpdump >/dev/null || { echo 'CAPTURE_BLOCKED: tcpdump is unavailable.' >&2; exit 77; }
if ! ip -4 -o addr show dev "$IFACE" | awk '{print $4}' | cut -d/ -f1 | grep -Fxq "$SOURCE_IP"; then
  echo "CAPTURE_BLOCKED: $IFACE does not have expected source IP $SOURCE_IP." >&2
  exit 77
fi
if [[ -e "$OUT" || -e "$OUT.partial.pcap" || -e "$OUT.capture.json" || -e "$MANIFEST" ]]; then
  echo 'CAPTURE_BLOCKED: refusing to overwrite existing evidence or manifest.' >&2
  exit 77
fi
mkdir -p "$(dirname "$OUT")"
PARTIAL="$OUT.partial.pcap"
LOG="$OUT.tcpdump.log"
META="$OUT.capture.json"
BPF="((src host $SOURCE_IP and dst host $TARGET_IP and tcp and dst portrange 18100-18123) or (src host $TARGET_IP and dst host $SOURCE_IP and tcp and src portrange 18100-18123))"
START_UTC=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)
TCPDUMP_PID=''
TIMER_PID=''
GENERATOR_STATUS=blocked
CAPTURE_STATUS=not_started

write_metadata() {
  END_UTC=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)
  CAPTURED=$(awk '/ packets captured/{print $1; exit}' "$LOG" 2>/dev/null || true)
  RECEIVED=$(awk '/ packets received by filter/{print $1; exit}' "$LOG" 2>/dev/null || true)
  DROPPED=$(awk '/ packets dropped by kernel/{print $1; exit}' "$LOG" 2>/dev/null || true)
  CAPTURED=${CAPTURED:-null}; RECEIVED=${RECEIVED:-null}; DROPPED=${DROPPED:-null}
  python3 - "$META" "$START_UTC" "$END_UTC" "$CAPTURE_STATUS" "$GENERATOR_STATUS" "$CAPTURED" "$RECEIVED" "$DROPPED" <<'PY'
import json, sys
path, start, end, capture_status, generator_status, captured, received, dropped = sys.argv[1:]
def number(value):
    return None if value == 'null' else int(value)
json.dump({
    'interface': 'eth1', 'source_ip': '192.168.10.20', 'target_ip': '192.168.10.10',
    'start_utc': start, 'end_utc': end, 'capture_exit_status': capture_status,
    'generator_exit_status': generator_status, 'duration_limit_seconds': 120,
    'packet_limit': 5000, 'snaplen': 96,
    'packet_count': number(captured),
    'drop_statistics': {'packets_captured': number(captured), 'packets_received_by_filter': number(received), 'packets_dropped_by_kernel': number(dropped)},
    'bpf': '((src host 192.168.10.20 and dst host 192.168.10.10 and tcp and dst portrange 18100-18123) or (src host 192.168.10.10 and dst host 192.168.10.20 and tcp and src portrange 18100-18123))',
}, open(path, 'w', encoding='utf-8'), indent=2)
PY
}

cleanup() {
  if [[ -n "$TIMER_PID" ]]; then kill "$TIMER_PID" 2>/dev/null || true; fi
  if [[ -n "$TCPDUMP_PID" ]] && kill -0 "$TCPDUMP_PID" 2>/dev/null; then
    kill -INT "$TCPDUMP_PID" 2>/dev/null || true
    wait "$TCPDUMP_PID" 2>/dev/null || true
  fi
  write_metadata
}
trap cleanup EXIT

# This is the only privileged command in the workflow, and it is intentionally
# interactive. Do not replace it with a persistent privilege or capability change.
sudo tcpdump -i "$IFACE" -s "$SNAPLEN" -n -U -w "$PARTIAL" -c "$MAX_PACKETS" "$BPF" 2>"$LOG" &
TCPDUMP_PID=$!
# Start the wall-clock bound immediately after tcpdump is launched, including
# the readiness wait, so the capture itself can never exceed 120 seconds.
(
  sleep "$MAX_SECONDS"
  kill -INT "$TCPDUMP_PID" 2>/dev/null || true
) &
TIMER_PID=$!
for _ in $(seq 1 150); do
  if grep -Fq "listening on $IFACE" "$LOG" 2>/dev/null; then break; fi
  if ! kill -0 "$TCPDUMP_PID" 2>/dev/null; then
    CAPTURE_STATUS=failed
    echo 'CAPTURE_BLOCKED: tcpdump exited before reporting readiness.' >&2
    exit 77
  fi
  sleep 0.1
done
if ! grep -Fq "listening on $IFACE" "$LOG" 2>/dev/null; then
  CAPTURE_STATUS=failed
  echo 'CAPTURE_BLOCKED: tcpdump did not report listening on eth1 within 15 seconds.' >&2
  exit 77
fi

set +e
"$ROOT/current/scripts/demo/vm2-generate-attack.sh" "$MANIFEST"
GENERATOR_STATUS=$?
set -e
if [[ $GENERATOR_STATUS -eq 0 ]]; then
  kill -INT "$TCPDUMP_PID" 2>/dev/null || true
fi
set +e
wait "$TCPDUMP_PID"
TCPDUMP_STATUS=$?
set -e
CAPTURE_STATUS=$TCPDUMP_STATUS
if [[ $TCPDUMP_STATUS -eq 0 && -s "$PARTIAL" ]]; then
  mv -- "$PARTIAL" "$OUT"
  SHA256=$(sha256sum "$OUT" | awk '{print $1}')
  echo "ATTACK_CAPTURE_READY: $OUT SHA256=$SHA256"
else
  echo "CAPTURE_PARTIAL: preserving $PARTIAL and $LOG" >&2
  exit 1
fi
if [[ $GENERATOR_STATUS -ne 0 ]]; then exit "$GENERATOR_STATUS"; fi
