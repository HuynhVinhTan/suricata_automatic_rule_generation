#!/usr/bin/env bash
set -euo pipefail
ROOT=/home/tanhv/suricata-ai-showcase/current
DATA=${1:-/home/tanhv/suricata-ai-showcase/datasets}
MODEL=${2:-/home/tanhv/suricata-ai-showcase/models/showcase_demo}
REPORT=${3:-/home/tanhv/suricata-ai-showcase/inference/showcase-model-report.json}
exec env PYTHONPATH="$ROOT/src" /home/tanhv/suricata-ai-venv/bin/python "$ROOT/scripts/train_showcase_model.py" \
  --development "$DATA/development/records.jsonl" --calibration "$DATA/calibration/records.jsonl" \
  --holdout "$DATA/holdout/records.jsonl" --artifact-dir "$MODEL" --report "$REPORT"
