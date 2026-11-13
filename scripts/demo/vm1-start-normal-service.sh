#!/usr/bin/env bash
set -euo pipefail
ROOT=${SHOWCASE_ROOT:-/home/tanhv/suricata-ai-showcase}
PORT=${1:-18080}
SERVICE_ROOT="$ROOT/runtime/normal-http"
PID_FILE="$ROOT/runtime/http-server.pid"
PORT_FILE="$ROOT/runtime/http-server.port"
[[ "$PORT" =~ ^[0-9]+$ && "$PORT" -ge 1024 && "$PORT" -le 65535 ]] || { echo 'Invalid unprivileged HTTP port' >&2; exit 64; }
mkdir -p "$SERVICE_ROOT" "$(dirname "$PID_FILE")"
printf '%s\n' 'suricata showcase normal service' > "$SERVICE_ROOT/index.html"
if [[ -f "$PID_FILE" ]]; then
  pid=$(cat "$PID_FILE")
  if [[ -r "/proc/$pid/cmdline" ]]; then echo "Normal service already running (PID $pid)"; exit 0; fi
  rm -f "$PID_FILE"
fi
nohup python3 -m http.server "$PORT" --bind 192.168.10.10 --directory "$SERVICE_ROOT" > "$ROOT/runtime/http-server.log" 2>&1 &
pid=$!
printf '%s\n' "$pid" > "$PID_FILE"
printf '%s\n' "$PORT" > "$PORT_FILE"
sleep 0.2
kill -0 "$pid"
echo "NORMAL_HTTP_SERVICE=RUNNING PID=$pid PORT=$PORT"
