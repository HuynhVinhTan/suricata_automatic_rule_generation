#!/usr/bin/env bash
set -euo pipefail
ROOT=/home/tanhv/suricata-ai-showcase
PID_FILE="$ROOT/runtime/isolated.pid"
if [[ -f "$PID_FILE" ]]; then
  pid=$(cat "$PID_FILE")
  if [[ -r "/proc/$pid/cmdline" ]] && tr '\0' ' ' < "/proc/$pid/cmdline" | grep -q "$ROOT"; then kill -TERM "$pid"; fi
  rm -f "$PID_FILE"
fi
echo 'ISOLATED_ROLLBACK=COMPLETE'
echo 'PRODUCTION_SERVICES=UNTOUCHED'
