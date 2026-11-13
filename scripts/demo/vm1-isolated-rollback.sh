#!/usr/bin/env bash
set -euo pipefail
ROOT=${SHOWCASE_ROOT:-/home/tanhv/suricata-ai-showcase}
PID_FILE="$ROOT/runtime/isolated.pid"
CANDIDATE=${1:-$ROOT/runtime/active-candidate.rules}
NEGATIVE_EVIDENCE=${2:-$ROOT/runtime/negative-replay.json}
PRODUCTION_BEFORE=${3:-$ROOT/runtime/production-before.sha256}
PRODUCTION_AFTER=${4:-$ROOT/runtime/production-after.sha256}

fail() { echo "ROLLBACK_NOT_VERIFIED: $*" >&2; echo 'PRODUCTION_SERVICES=UNKNOWN'; exit 77; }
[[ -f "$CANDIDATE" ]] || fail 'candidate artifact was not present before rollback'

if [[ -f "$PID_FILE" ]]; then
  pid=$(cat "$PID_FILE")
  [[ "$pid" =~ ^[0-9]+$ ]] || fail 'isolated PID is invalid'
  if [[ -r "/proc/$pid/cmdline" ]]; then
    tr '\0' ' ' < "/proc/$pid/cmdline" | grep -Fq "$ROOT" || fail 'PID is not showcase-owned'
    kill -TERM "$pid" 2>/dev/null || true
    for _ in {1..20}; do [[ ! -r "/proc/$pid/cmdline" ]] && break; sleep 0.1; done
    [[ ! -r "/proc/$pid/cmdline" ]] || fail 'isolated process did not stop'
  fi
  rm -f "$PID_FILE"
fi

rm -f -- "$CANDIDATE"
[[ ! -e "$CANDIDATE" ]] || fail 'candidate artifact remains after removal'
[[ -s "$NEGATIVE_EVIDENCE" ]] || fail 'negative replay evidence is missing'
grep -Fq '"replay_status": "pass"' "$NEGATIVE_EVIDENCE" || fail 'negative replay did not pass'
grep -Fq '"candidate_sid_alerts": 0' "$NEGATIVE_EVIDENCE" || fail 'negative replay still contains candidate alerts'
[[ -f "$PRODUCTION_BEFORE" && -f "$PRODUCTION_AFTER" ]] || fail 'production invariant snapshots are missing'
cmp -s "$PRODUCTION_BEFORE" "$PRODUCTION_AFTER" || fail 'production invariants changed'
echo 'ISOLATED_ROLLBACK=VERIFIED'
echo 'PRODUCTION_SERVICES=UNCHANGED'
