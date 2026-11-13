#!/usr/bin/env bash
set -euo pipefail
ROOT=${SHOWCASE_ROOT:-/home/tanhv/suricata-ai-showcase}
PID_FILE="$ROOT/runtime/isolated.pid"
CANDIDATE=${1:-$ROOT/runtime/active-candidate.rules}
NEGATIVE_EVIDENCE=${2:-$ROOT/runtime/negative-replay.json}
PRODUCTION_BEFORE=${3:-$ROOT/runtime/production-before.sha256}
PRODUCTION_AFTER=${4:-$ROOT/runtime/production-after.sha256}
CANDIDATE_METADATA=${5:-$ROOT/runtime/candidate-metadata.json}

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
python3 - "$CANDIDATE_METADATA" "$NEGATIVE_EVIDENCE" <<'PY'
import json
import re
import sys
from datetime import datetime

metadata_path, evidence_path = sys.argv[1:]
try:
    metadata = json.loads(open(metadata_path, encoding='utf-8').read())
    evidence = json.loads(open(evidence_path, encoding='utf-8').read())
except (OSError, json.JSONDecodeError) as exc:
    raise SystemExit(f'candidate-specific evidence is invalid: {exc}')
required = ('candidate_id', 'candidate_sid', 'rule_sha256', 'pcap_sha256', 'run_id')
missing = [name for name in required if not metadata.get(name)]
if missing:
    raise SystemExit(f'candidate metadata missing: {", ".join(missing)}')
for name in ('rule_sha256', 'pcap_sha256'):
    if not re.fullmatch(r'[0-9a-fA-F]{64}', str(metadata[name])):
        raise SystemExit(f'invalid {name}')
for name in required:
    if evidence.get(name) != metadata[name]:
        raise SystemExit(f'evidence {name} does not match candidate metadata')
if evidence.get('candidate_sid') != metadata['candidate_sid']:
    raise SystemExit('candidate SID mismatch')
if evidence.get('runtime_scope') != 'isolated':
    raise SystemExit('rollback evidence is not isolated-scope')
if evidence.get('replay_mode') != 'fresh_negative_replay' or evidence.get('generated_after_rollback') is not True:
    raise SystemExit('negative replay evidence is stale or not post-rollback')
if evidence.get('candidate_sid_alerts') != 0:
    raise SystemExit('candidate SID alerts are non-zero')
timestamp = evidence.get('post_rollback_timestamp')
if not isinstance(timestamp, str):
    raise SystemExit('post_rollback_timestamp is missing')
try:
    datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
except ValueError as exc:
    raise SystemExit('post_rollback_timestamp is invalid') from exc
invariants = evidence.get('production_invariants')
if not isinstance(invariants, dict) or not all(invariants.get(key) for key in ('yaml_sha256', 'rules_sha256', 'pid')):
    raise SystemExit('production YAML/rules/PID invariants are missing')
PY
echo 'ISOLATED_ROLLBACK=VERIFIED'
echo 'PRODUCTION_SERVICES=UNCHANGED'
