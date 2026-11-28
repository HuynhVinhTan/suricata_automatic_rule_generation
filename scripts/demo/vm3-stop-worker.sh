#!/usr/bin/env bash
set -euo pipefail
PID_FILE=/home/tanhv/suricata-ai-showcase/runtime/worker.pid
if [[ -f "$PID_FILE" ]]; then
  pid=$(cat "$PID_FILE")
  if [[ -r "/proc/$pid/cmdline" ]] && tr '\0' ' ' < "/proc/$pid/cmdline" | grep -q 'suricata-ai-showcase'; then kill -TERM "$pid"; fi
  rm -f "$PID_FILE"
fi
echo 'WORKER_STOPPED=YES'
