#!/usr/bin/env bash
set -euo pipefail
ROOT=/home/tanhv/suricata-ai-showcase
INPUT=${1:-$ROOT/inference/inference.jsonl}
INDEX="suricata-ai-showcase-$(date -u +%Y.%m.%d)"
python3 - "$INPUT" "$INDEX" <<'PY'
import json, subprocess, sys
path, index = sys.argv[1:]
lines=[]
for line in open(path, encoding='utf-8'):
    if line.strip():
        lines += [json.dumps({'index': {'_index': index}}), line.rstrip()]
if not lines:
    print('INDEXED_INFERENCE_RECORDS=0'); raise SystemExit
payload='\n'.join(lines)+'\n'
result=subprocess.run(['curl','-fsS','-H','Content-Type: application/x-ndjson','--data-binary','@-', 'http://127.0.0.1:9200/_bulk'], input=payload, text=True, capture_output=True, check=True)
print('INDEX='+index)
print('INDEX_RESPONSE='+result.stdout[:500])
print('INDEXED_INFERENCE_RECORDS='+str(len(lines)//2))
PY
