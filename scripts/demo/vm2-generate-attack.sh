#!/usr/bin/env bash
set -euo pipefail
ROOT=/home/kali/suricata-ai-showcase/current
OUT=${1:-/home/kali/suricata-ai-showcase/evidence/attack-$(date -u +%Y%m%dT%H%M%SZ).json}
mkdir -p "$(dirname "$OUT")"
PYTHONPATH="$ROOT/src" python3 "$ROOT/scripts/lab_slow_port_scan.py" --run-id "showcase-attack-$(date -u +%Y%m%dT%H%M%SZ)" --target 192.168.10.10 --ports 18100,18101,18102,18103,18104,18105,18106,18107,18108,18109,18110,18111,18112,18113,18114,18115,18116,18117,18118,18119,18120,18121,18122,18123 --source-ip 192.168.10.20 --interval 2 --out "$OUT"
