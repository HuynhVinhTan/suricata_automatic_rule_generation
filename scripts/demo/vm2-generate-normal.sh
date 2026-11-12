#!/usr/bin/env bash
set -euo pipefail
ROOT=/home/kali/suricata-ai-showcase/current
OUT=${1:-/home/kali/suricata-ai-showcase/evidence/normal-$(date -u +%Y%m%dT%H%M%SZ).json}
mkdir -p "$(dirname "$OUT")"
PYTHONPATH="$ROOT/src" python3 "$ROOT/scripts/lab_normal_service_access.py" --run-id "showcase-normal-$(date -u +%Y%m%dT%H%M%SZ)" --target 192.168.10.10 --open-port 80 --closed-ports 18100,18101 --source-ip 192.168.10.20 --out "$OUT"
