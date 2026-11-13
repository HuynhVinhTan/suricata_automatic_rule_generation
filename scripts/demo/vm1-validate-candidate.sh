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
mkdir -p "$ROOT/runtime/validation"
suricata -T --init-errors-fatal -c "$CONFIG" -l "$ROOT/runtime/validation"
if [[ -n "$PCAP" ]]; then
  [[ -f "$PCAP" ]] || exit 66
  suricata -k none -r "$PCAP" -c "$CONFIG" -l "$ROOT/runtime/validation/replay"
fi
echo 'ISOLATED_VALIDATION=PASS'
