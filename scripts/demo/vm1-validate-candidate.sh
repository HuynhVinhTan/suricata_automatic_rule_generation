#!/usr/bin/env bash
set -euo pipefail
ROOT=${SHOWCASE_ROOT:-/home/tanhv/suricata-ai-showcase}
CONFIG=${1:-}; RULES=${2:-}; PCAP=${3:-}
[[ -n "$CONFIG" && -n "$RULES" ]] || { echo 'Usage: vm1-validate-candidate.sh <isolated-config> <isolated-rules> [pcap]' >&2; exit 64; }
ROOT=$(realpath -e -- "$ROOT") || { echo 'Showcase root is missing' >&2; exit 66; }
canonicalize_input() {
  local label=$1 path=$2 resolved
  resolved=$(realpath -e -- "$path") || { echo "$label is missing or cannot be canonicalized" >&2; exit 66; }
  case "$resolved" in
    "$ROOT"/*) printf '%s\n' "$resolved" ;;
    *) echo "$label must be inside the allowlisted root" >&2; exit 77 ;;
  esac
}
CONFIG=$(canonicalize_input CONFIG "$CONFIG")
RULES=$(canonicalize_input RULES "$RULES")
if [[ -n "$PCAP" ]]; then PCAP=$(canonicalize_input PCAP "$PCAP"); fi
python3 - "$CONFIG" "$RULES" <<'PY'
from pathlib import Path
import sys

config = Path(sys.argv[1]).resolve()
rules = Path(sys.argv[2]).resolve()
default_path = Path('.')
references = []
in_rule_files = False
for raw in config.read_text(encoding='utf-8').splitlines():
    line = raw.split('#', 1)[0].rstrip()
    stripped = line.strip()
    if not stripped:
        continue
    if stripped.startswith('default-rule-path:'):
        default_path = Path(stripped.split(':', 1)[1].strip().strip('"\''))
        continue
    if stripped == 'rule-files:':
        in_rule_files = True
        continue
    if in_rule_files:
        if stripped.startswith('- '):
            references.append(stripped[2:].strip().strip('"\''))
        elif not raw.startswith((' ', '\t')):
            in_rule_files = False
base = default_path if default_path.is_absolute() else config.parent / default_path
resolved = {(base / item).resolve() for item in references}
if rules not in resolved:
    raise SystemExit(f'RULES not referenced by config rule-files: {rules}')
PY
mkdir -p "$ROOT/runtime/validation"
rm -f "$ROOT/runtime/validation/suricata.log"
CONSOLE_LOG="$ROOT/runtime/validation/suricata-console.log"
(cd "$(dirname "$CONFIG")" && suricata -T --init-errors-fatal -c "$CONFIG" -l "$ROOT/runtime/validation") 2>&1 | tee "$CONSOLE_LOG"
VALIDATION_LOG="$ROOT/runtime/validation/suricata.log"
[[ -s "$VALIDATION_LOG" ]] || { echo 'Suricata did not produce validation log output' >&2; exit 77; }
grep -Fq "Loading rule file: ./$(basename "$RULES")" "$VALIDATION_LOG" || { echo "Suricata did not load supplied rule file $(basename "$RULES")" >&2; exit 77; }
mapfile -t CANDIDATE_SIDS < <(grep -Eo 'sid:[[:space:]]*[0-9]+' "$RULES" | awk -F: '{gsub(/[[:space:]]/, "", $2); print $2}' | sort -u)
[[ "${#CANDIDATE_SIDS[@]}" -gt 0 ]] || { echo 'Candidate rules contain no SID' >&2; exit 77; }
loaded=$(grep -Eo '[0-9]+ rules successfully loaded' "$VALIDATION_LOG" | tail -1 | awk '{print $1}')
[[ "$loaded" =~ ^[0-9]+$ && "$loaded" -ge "${#CANDIDATE_SIDS[@]}" ]] || { echo 'Suricata loaded fewer rules than supplied candidate SIDs' >&2; exit 77; }
for sid in "${CANDIDATE_SIDS[@]}"; do echo "CANDIDATE_SID_LOADED=$sid RULES=$RULES"; done
if [[ -n "$PCAP" ]]; then
  [[ -f "$PCAP" ]] || exit 66
  suricata -k none -r "$PCAP" -c "$CONFIG" -l "$ROOT/runtime/validation/replay"
fi
echo 'ISOLATED_VALIDATION=PASS'
