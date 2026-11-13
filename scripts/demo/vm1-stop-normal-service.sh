#!/usr/bin/env bash
set -euo pipefail
ROOT=${SHOWCASE_ROOT:-/home/tanhv/suricata-ai-showcase}
PID_FILE="$ROOT/runtime/http-server.pid"
if [[ -f "$PID_FILE" ]]; then
  pid=$(cat "$PID_FILE")
  if [[ -r "/proc/$pid/cmdline" ]]; then
    tr '\0' ' ' < "/proc/$pid/cmdline" | grep -Fq "$ROOT" || { echo 'Refusing non-showcase HTTP process' >&2; exit 77; }
    kill -TERM "$pid" 2>/dev/null || true
  fi
  rm -f "$PID_FILE" "$ROOT/runtime/http-server.port"
fi
echo 'NORMAL_HTTP_SERVICE=STOPPED'
