#!/usr/bin/env bash
set -euo pipefail

# Owner-invoked VM2-only workflow. Authentication is deliberately foreground
# and interactive; the bounded capture is supervised as a process group.
ROOT=${SHOWCASE_ROOT:-/home/kali/suricata-ai-showcase}
IFACE=eth1
SOURCE_IP=192.168.10.20
TARGET_IP=192.168.10.10
MAX_SECONDS=120
MAX_PACKETS=5000
SNAPLEN=96
GENERATOR_TIMEOUT_SECONDS=90
READINESS_WAIT_ITERATIONS=${READINESS_WAIT_ITERATIONS:-150}
OUT=${1:-$ROOT/evidence/attack-$(date -u +%Y%m%dT%H%M%SZ).pcap}
MANIFEST=${2:-$ROOT/evidence/$(basename "${OUT%.pcap}").json}
PARTIAL="$OUT.partial.pcap"
LOG="$OUT.tcpdump.log"
META="$OUT.capture.json"
REPORT="$OUT.verification.json"
TIMEOUT_MARKER="$OUT.timeout"
STOP_REQUEST="$OUT.stop"
SUPERVISOR=/usr/local/libexec/suricata-ai-showcase/vm2-capture-supervisor
BPF="((src host $SOURCE_IP and dst host $TARGET_IP and tcp and dst portrange 18100-18123) or (src host $TARGET_IP and dst host $SOURCE_IP and tcp and src portrange 18100-18123))"
TCPDUMP_SUPERVISOR_PID=''
GENERATOR_STATUS=blocked
CAPTURE_STATUS=not_started
CAPTURE_WAIT_STATUS=not_waited
FINALIZED=0

if [[ ! -t 0 || ! -t 1 ]]; then
  echo 'CAPTURE_BLOCKED: interactive PTY required. Re-run as: ssh -tt suricata-vm2 /home/kali/suricata-ai-showcase/current/scripts/demo/vm2-capture-session.sh' >&2
  exit 77
fi
if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
  echo 'CAPTURE_BLOCKED: invoke as the owner user; only tcpdump may run through sudo.' >&2
  exit 77
fi
command -v ip >/dev/null || { echo 'CAPTURE_BLOCKED: ip command is unavailable.' >&2; exit 77; }
command -v tcpdump >/dev/null || { echo 'CAPTURE_BLOCKED: tcpdump is unavailable.' >&2; exit 77; }
command -v timeout >/dev/null || { echo 'CAPTURE_BLOCKED: timeout is unavailable.' >&2; exit 77; }
command -v sha256sum >/dev/null || { echo 'CAPTURE_BLOCKED: sha256sum is unavailable.' >&2; exit 77; }
if ! ip -4 -o addr show dev "$IFACE" | awk '{print $4}' | cut -d/ -f1 | grep -Fxq "$SOURCE_IP"; then
  echo "CAPTURE_BLOCKED: $IFACE does not have expected source IP $SOURCE_IP." >&2
  exit 77
fi
if [[ -e "$OUT" || -e "$PARTIAL" || -e "$META" || -e "$REPORT" || -e "$TIMEOUT_MARKER" || -e "$STOP_REQUEST" || -e "$MANIFEST" ]]; then
  echo 'CAPTURE_BLOCKED: refusing to overwrite existing evidence, report, or manifest.' >&2
  exit 77
fi
mkdir -p "$(dirname "$OUT")"

write_metadata() {
  local end_utc captured received dropped
  end_utc=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)
  captured=$(awk '/ packets captured/{print $1; exit}' "$LOG" 2>/dev/null || true)
  received=$(awk '/ packets received by filter/{print $1; exit}' "$LOG" 2>/dev/null || true)
  dropped=$(awk '/ packets dropped by kernel/{print $1; exit}' "$LOG" 2>/dev/null || true)
  captured=${captured:-null}; received=${received:-null}; dropped=${dropped:-null}
  python3 - "$META" "${START_UTC:-}" "$end_utc" "$CAPTURE_STATUS" "$GENERATOR_STATUS" "$captured" "$received" "$dropped" <<'PY'
import json, sys
path, start, end, capture_status, generator_status, captured, received, dropped = sys.argv[1:]
def number(value):
    return None if value == "null" else int(value)
json.dump({
    "interface": "eth1", "source_ip": "192.168.10.20", "target_ip": "192.168.10.10",
    "start_utc": start, "end_utc": end, "capture_exit_status": capture_status,
    "generator_exit_status": generator_status, "duration_limit_seconds": 120,
    "packet_limit": 5000, "snaplen": 96, "packet_count": number(captured),
    "drop_statistics": {"packets_captured": number(captured), "packets_received_by_filter": number(received), "packets_dropped_by_kernel": number(dropped)},
    "bpf": "((src host 192.168.10.20 and dst host 192.168.10.10 and tcp and dst portrange 18100-18123) or (src host 192.168.10.10 and dst host 192.168.10.20 and tcp and src portrange 18100-18123))",
}, open(path, "w", encoding="utf-8"), indent=2)
PY
}

terminate_capture() {
  if [[ -z "$TCPDUMP_SUPERVISOR_PID" ]]; then return; fi
  touch "$STOP_REQUEST"
  set +e
  wait "$TCPDUMP_SUPERVISOR_PID" 2>/dev/null
  CAPTURE_WAIT_STATUS=$?
  set -e
}

cleanup() {
  [[ "$FINALIZED" -eq 1 ]] || terminate_capture
  [[ -f "$LOG" ]] && write_metadata || true
  rm -f "$STOP_REQUEST" 2>/dev/null || true
}
trap 'CAPTURE_STATUS=interrupted; exit 130' INT TERM
trap cleanup EXIT

START_UTC=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)
# Foreground owner authentication. This is the only interactive sudo action.
if ! sudo -v; then
  CAPTURE_STATUS=authentication_failed
  echo 'CAPTURE_BLOCKED: sudo authentication failed.' >&2
  exit 77
fi
if [[ ! -x "$SUPERVISOR" ]]; then
  CAPTURE_STATUS=supervisor_missing
  echo 'CAPTURE_BLOCKED: privileged capture supervisor is unavailable.' >&2
  exit 77
fi

# Reuse the foreground ticket, fail closed if unavailable, and delegate all
# privileged signal escalation and reaping to the supervisor itself.
sudo -n "$SUPERVISOR" --output "$PARTIAL" --stop-file "$STOP_REQUEST" 2>"$LOG" &
TCPDUMP_SUPERVISOR_PID=$!

for _ in $(seq 1 "$READINESS_WAIT_ITERATIONS"); do
  if grep -Fq "listening on $IFACE" "$LOG" 2>/dev/null; then break; fi
  if ! kill -0 "$TCPDUMP_SUPERVISOR_PID" 2>/dev/null; then
    CAPTURE_STATUS=readiness_failed
    echo 'CAPTURE_BLOCKED: tcpdump exited before reporting readiness.' >&2
    exit 77
  fi
  sleep 0.1
done
if ! grep -Fq "listening on $IFACE" "$LOG" 2>/dev/null; then
  CAPTURE_STATUS=readiness_timeout
  echo 'CAPTURE_BLOCKED: readiness timeout; tcpdump did not report listening on eth1 within 15 seconds.' >&2
  exit 77
fi

set +e
timeout --signal=TERM --kill-after=5 "$GENERATOR_TIMEOUT_SECONDS" "$ROOT/current/scripts/demo/vm2-generate-attack.sh" "$MANIFEST"
GENERATOR_STATUS=$?
set -e
terminate_capture
CAPTURE_STATUS=$CAPTURE_WAIT_STATUS
if [[ "$CAPTURE_WAIT_STATUS" == "124" ]]; then
  CAPTURE_STATUS=timeout
  touch "$TIMEOUT_MARKER"
fi
write_metadata

if [[ "$GENERATOR_STATUS" -ne 0 || "$CAPTURE_STATUS" != "0" || ! -s "$PARTIAL" ]]; then
  echo "CAPTURE_PARTIAL: preserving $PARTIAL, $LOG, and $META" >&2
  exit 1
fi

# Verify the actual partial PCAP before publishing it under its final name.
if ! python3 "$ROOT/current/scripts/verify_attack_evidence.py" --pcap "$PARTIAL" --manifest "$MANIFEST" --capture-metadata "$META" --report "$REPORT"; then
  CAPTURE_STATUS=validation_failed
  echo "CAPTURE_BLOCKED: strict PCAP/manifest verification failed; preserving partial evidence." >&2
  exit 1
fi
SHA256=$(sha256sum "$PARTIAL" | awk '{print $1}')
mv -- "$PARTIAL" "$OUT"
FINALIZED=1
echo "ATTACK_CAPTURE_READY: $OUT SHA256=$SHA256"
