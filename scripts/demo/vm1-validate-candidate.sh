#!/usr/bin/env bash
set -euo pipefail
ROOT=/home/tanhv/suricata-ai-showcase
CONFIG=${1:-}; RULES=${2:-}; PCAP=${3:-}
[[ -n "$CONFIG" && -n "$RULES" ]] || { echo 'Usage: vm1-validate-candidate.sh <isolated-config> <isolated-rules> [pcap]' >&2; exit 64; }
case "$CONFIG:$RULES${PCAP:+:$PCAP}" in "$ROOT"/*) ;; *) echo 'Refusing paths outside showcase root' >&2; exit 77;; esac
[[ -f "$CONFIG" && -f "$RULES" ]] || { echo 'Candidate inputs are missing' >&2; exit 66; }
mkdir -p "$ROOT/runtime/validation"
suricata -T --init-errors-fatal -c "$CONFIG" -l "$ROOT/runtime/validation"
if [[ -n "$PCAP" ]]; then
  [[ -f "$PCAP" ]] || exit 66
  suricata -k none -r "$PCAP" -c "$CONFIG" -l "$ROOT/runtime/validation/replay"
fi
echo 'ISOLATED_VALIDATION=PASS'
