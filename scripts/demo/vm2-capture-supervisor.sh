#!/usr/bin/env bash
set -u

# Privileged supervisor: sudo -n is invoked only after foreground sudo -v.
PIDFILE=$1
STOPFILE=$2
TIMEOUT_MARKER=$3
STATUSFILE=$4
MAX_SECONDS=$5
shift 5
[[ ${1:-} == "--" ]] || exit 64
shift
CHILD_WRAPPER_PID=''
CAPTURE_PID=''
WATCHDOG_PID=''
STOP_STATUS=0

write_status() { printf '%s\n' "$1" > "$STATUSFILE"; }
child_alive() { [[ -n "$CHILD_WRAPPER_PID" ]] && kill -0 "$CHILD_WRAPPER_PID" 2>/dev/null; }
read_capture_pid() {
  [[ -s "$PIDFILE" ]] || return 1
  CAPTURE_PID=$(cat "$PIDFILE" 2>/dev/null || true)
  [[ "$CAPTURE_PID" =~ ^[0-9]+$ ]]
}
stop_capture() {
  local signal=$1
  if read_capture_pid; then
    kill -"$signal" -- "-$CAPTURE_PID" 2>/dev/null || true
  elif child_alive; then
    kill -"$signal" "$CHILD_WRAPPER_PID" 2>/dev/null || true
  fi
}
escalate_and_reap() {
  local waited
  stop_capture INT
  for waited in $(seq 1 30); do
    child_alive || return 0
    sleep 0.1
  done
  stop_capture TERM
  for waited in $(seq 1 10); do
    child_alive || return 0
    sleep 0.1
  done
  stop_capture KILL
  for waited in $(seq 1 10); do
    child_alive || return 0
    sleep 0.1
  done
  return 1
}
finish() {
  local status=$1
  if [[ -n "$WATCHDOG_PID" ]]; then
    kill "$WATCHDOG_PID" 2>/dev/null || true
    wait "$WATCHDOG_PID" 2>/dev/null || true
  fi
  if child_alive && ! escalate_and_reap; then status=125; fi
  if [[ -n "$CHILD_WRAPPER_PID" ]]; then
    wait "$CHILD_WRAPPER_PID" 2>/dev/null || true
  fi
  rm -f "$PIDFILE"
  write_status "$status"
  exit "$status"
}
on_signal() { STOP_STATUS=130; finish "$STOP_STATUS"; }
trap on_signal INT TERM

setsid --wait bash -c 'printf "%s\n" "$$" > "$1"; shift; exec "$@"' \
  capture-child "$PIDFILE" "$@" &
CHILD_WRAPPER_PID=$!
(
  sleep "$MAX_SECONDS"
  touch "$TIMEOUT_MARKER"
  touch "$STOPFILE"
) &
WATCHDOG_PID=$!
while child_alive; do
  if [[ -e "$STOPFILE" ]]; then
    [[ -e "$TIMEOUT_MARKER" ]] && STOP_STATUS=124
    finish "$STOP_STATUS"
  fi
  sleep 0.1
done
set +e
wait "$CHILD_WRAPPER_PID"
CAPTURE_STATUS=$?
set -e
finish "$CAPTURE_STATUS"
