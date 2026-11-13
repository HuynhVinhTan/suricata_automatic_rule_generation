#!/usr/bin/env bash
set -euo pipefail
curl -fsS http://127.0.0.1:5601/api/status | python3 -c 'import json,sys; d=json.load(sys.stdin); print("KIBANA_STATUS="+d.get("status",{}).get("overall",{}).get("level","unknown"))'
echo 'KIBANA_URL=http://127.0.0.1:5601/app/discover'
echo 'DEMO_INDEX=suricata-ai-showcase-*'
