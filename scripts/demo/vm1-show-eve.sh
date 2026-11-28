#!/usr/bin/env bash
set -euo pipefail
python3 - /var/log/suricata/eve.json <<'PY'
import json, sys
from collections import Counter
counts=Counter(); last=None
with open(sys.argv[1], 'rb') as stream:
    for raw in stream.readlines()[-200:]:
        try: event=json.loads(raw)
        except Exception: continue
        counts[event.get('event_type','unknown')]+=1
        last=(event.get('timestamp'), event.get('event_type'))
print('RECENT_EVENT_TYPES='+json.dumps(counts, sort_keys=True))
print('LAST_EVENT='+json.dumps(last))
PY
