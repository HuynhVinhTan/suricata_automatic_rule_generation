#!/usr/bin/env bash
set -euo pipefail
ROOT=/home/kali/suricata-ai-showcase/current
OUT=${1:-/home/kali/suricata-ai-showcase/evidence/normal-$(date -u +%Y%m%dT%H%M%SZ).json}
HTTP_PORT=${SHOWCASE_HTTP_PORT:-18080}
mkdir -p "$(dirname "$OUT")"
[[ "$HTTP_PORT" =~ ^[0-9]+$ ]] || { echo 'SHOWCASE_HTTP_PORT must be numeric' >&2; exit 64; }
PYTHONPATH="$ROOT/src" python3 "$ROOT/scripts/lab_normal_service_access.py" --run-id "showcase-normal-$(date -u +%Y%m%dT%H%M%SZ)" --target 192.168.10.10 --open-port "$HTTP_PORT" --closed-ports 18100,18101 --source-ip 192.168.10.20 --out "$OUT"
python3 - "$OUT" <<'PY'
import json, sys
path = sys.argv[1]
with open(path, encoding='utf-8') as stream:
    data = json.load(stream)
if data.get('attempt_count') != 24 or data.get('http_200_count') != 22:
    raise SystemExit(f"INCOMPLETE_NORMAL_SESSION: attempts={data.get('attempt_count')} http_200={data.get('http_200_count')}")
print(f"NORMAL_SESSION=COMPLETE attempts=24 http_200=22 rst_refused={data.get('rst_refused_count', 0)}")
PY
