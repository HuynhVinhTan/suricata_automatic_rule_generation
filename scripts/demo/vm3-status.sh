#!/usr/bin/env bash
set -euo pipefail
echo "HOST=$(hostname) USER=$(id -un)"
test -x /home/tanhv/suricata-ai-venv/bin/python && /home/tanhv/suricata-ai-venv/bin/python --version || echo 'VENV=missing'
curl -fsS -o /dev/null -w 'ELASTICSEARCH_HTTP=%{http_code}\n' http://127.0.0.1:9200
curl -fsS -o /dev/null -w 'KIBANA_HTTP=%{http_code}\n' http://127.0.0.1:5601
find /home/tanhv/suricata-ai-showcase -maxdepth 3 -type f -name '*.jsonl' -printf 'EVE_SHADOW=%p SIZE=%s\n' 2>/dev/null || true
df -h / /home
