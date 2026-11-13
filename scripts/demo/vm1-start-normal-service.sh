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
printf '%s\n' 'ok' > "$SERVICE_ROOT/health"
if [[ -f "$PID_FILE" ]]; then
  pid=$(cat "$PID_FILE")
  if [[ -r "/proc/$pid/cmdline" ]]; then
    tr '\0' ' ' < "/proc/$pid/cmdline" | grep -Fq "$SERVICE_ROOT" || { echo 'Refusing PID not owned by the showcase HTTP service' >&2; exit 77; }
    echo "Normal service already running (PID $pid)"
    exit 0
  fi
  rm -f "$PID_FILE"
fi
nohup python3 -m http.server "$PORT" --bind 192.168.10.10 --directory "$SERVICE_ROOT" > "$ROOT/runtime/http-server.log" 2>&1 &
pid=$!
printf '%s\n' "$pid" > "$PID_FILE"
printf '%s\n' "$PORT" > "$PORT_FILE"
for _ in {1..20}; do
  if [[ -r "/proc/$pid/cmdline" ]] && tr '\0' ' ' < "/proc/$pid/cmdline" | grep -Fq "$SERVICE_ROOT" && curl -fsS --max-time 1 "http://192.168.10.10:$PORT/health" >/dev/null; then
    echo "NORMAL_HTTP_SERVICE=RUNNING PID=$pid PORT=$PORT"
    exit 0
  fi
  sleep 0.1
done
rm -f "$PID_FILE" "$PORT_FILE"
kill "$pid" 2>/dev/null || true
echo 'NORMAL_HTTP_SERVICE=FAILED_TO_BIND_OR_HEALTHCHECK' >&2
exit 75
