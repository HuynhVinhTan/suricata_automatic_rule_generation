#!/usr/bin/env bash
set -euo pipefail
ROOT=/home/tanhv/suricata-ai-showcase/current
MODEL=${1:-/home/tanhv/suricata-ai-showcase/models/showcase_demo}
INPUT=${2:-/home/tanhv/suricata-ai-showcase/eve-shadow/eve-shadow.jsonl}
PROFILE=${3:-showcase_demo}
OUT=/home/tanhv/suricata-ai-showcase/inference/inference.jsonl
LEDGER=/home/tanhv/suricata-ai-showcase/inference/ledger.sqlite3
if [[ ! -f "$MODEL/metadata.json" || ! -f "$MODEL/pipeline.joblib" ]]; then
  echo 'ML_BLOCKED: no verified compatible four-feature demo artifact at requested model path.' >&2
  exit 77
fi
mkdir -p "$(dirname "$OUT")"
nohup env PYTHONPATH="$ROOT/src" /home/tanhv/suricata-ai-venv/bin/python "$ROOT/scripts/infer_eve_stream.py" --profile "$PROFILE" --input "$INPUT" --model-dir "$MODEL" --output "$OUT" --ledger-path "$LEDGER" --run-id "showcase-$(date -u +%Y%m%dT%H%M%SZ)" --max-records-per-cycle 64 --max-bytes-per-cycle 1048576 --poll-interval 0.5 > /home/tanhv/suricata-ai-showcase/runtime/worker.log 2>&1 &
echo $! > /home/tanhv/suricata-ai-showcase/runtime/worker.pid
echo "WORKER_PID=$(cat /home/tanhv/suricata-ai-showcase/runtime/worker.pid)"
