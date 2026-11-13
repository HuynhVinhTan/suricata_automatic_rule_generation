#!/usr/bin/env bash
set -euo pipefail
path=/home/tanhv/suricata-ai-showcase/inference/inference.jsonl
[[ -f "$path" ]] || { echo 'INFERENCE_OUTPUT=NOT_PRESENT'; exit 77; }
wc -l "$path"
tail -n 5 "$path" | sed -E 's/"(src_ip|dest_ip|source_ip|destination_ip)"[[:space:]]*:[[:space:]]*"[^"]+"/"\1":"REDACTED"/g'
