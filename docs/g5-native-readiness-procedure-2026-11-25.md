# G5 native readiness procedure (non-live)

This procedure is for the owner on VM1 only. It does not consume an
authorization nonce, read a private key, start a daemon, open the control
socket, capture traffic, replay a PCAP, activate a rule, or modify production.
It must be completed before any separately reviewed authorization decision.

The original failed experiment and its evidence remain immutable:

- Failure JSON SHA-256: `44baca73ab8a25d287bd343f103107ffd01fd24e8d492911dd454271baec0177`
- Audit ledger SHA-256: `5b6b90da08efd9088c1bb5bd6a266e8c0a60fa64c7642d3786e99e2edd6fcb7b`

## 1. Set paths without using credentials

Run locally on VM1, with repository and isolated-root paths adjusted only to
their reviewed VM1 locations:

```bash
cd /home/tanhv/suricata-rule-review/repository
ROOT=/home/tanhv/suricata-rule-review/isolated-lifecycle-9103005
ATTEMPT_ID=g5-readiness-20261125-01
TEMPLATE_CONFIG="$ROOT/isolated.yaml"
CANDIDATE_RULES="$ROOT/evidence/candidate.rules"
READINESS_REPORT="$ROOT/readiness/$ATTEMPT_ID/native-readiness.json"
```

`ATTEMPT_ID` must be new. Do not use the prior failed attempt identifier or
the consumed authorization nonce. Confirm the future runtime namespace is
unused, without creating it:

```bash
test ! -e "$ROOT/attempts/$ATTEMPT_ID"
test -f "$TEMPLATE_CONFIG"
test -f "$CANDIDATE_RULES"
```

The candidate rule file must be the reviewed isolated candidate, never a file
under `/etc/suricata`, `/var/lib/suricata`, `/run/suricata`, or
`/var/run/suricata`.

## 2. Run the standalone native readiness validator

```bash
PYTHONPATH=src python3 -m scripts.validate_g5_native_readiness \
  --template-config "$TEMPLATE_CONFIG" \
  --isolated-root "$ROOT" \
  --attempt-id "$ATTEMPT_ID" \
  --candidate-rules "$CANDIDATE_RULES" \
  --suricata /usr/bin/suricata \
  --report "$READINESS_REPORT"
```

The validator performs only these native commands:

```bash
/usr/bin/suricata -V
/usr/bin/suricata -T --init-errors-fatal \
  -c "$ROOT/readiness/$ATTEMPT_ID/suricata.yaml" \
  -S "$CANDIDATE_RULES" \
  -l "$ROOT/readiness/$ATTEMPT_ID/logs"
```

The `-S` option is deliberately limited to syntax/offline validation. There
is no daemon command, no `-r`, no `tcpreplay`, no live `-s`/`-S` reload, and no
production socket.

## 3. Inspect the readiness result

```bash
python3 - "$READINESS_REPORT" <<'PY'
import json, pathlib, sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert report["status"] == "READY_FOR_REVIEWED_AUTHORIZATION"
assert report["live_operation"] is False
assert report["activation_attempted"] is False
assert report["traffic_replay_attempted"] is False
assert report["nonce_consumed"] is False
assert report["suricata_version"] == "8.0.3"
assert report["future_attempt_root"].endswith("/attempts/" + report["attempt_id"])
print("native readiness: PASS; no authorization consumed")
PY
```

Then inspect the effective YAML and require all of the following before any
owner decision:

- `af-packet` explicitly contains only `interface: lo`;
- `default-rule-path` is the readiness namespace’s `rules` directory;
- `rule-files` is exactly `[active.rules]`;
- `unix-command.enabled` is true and its filename is the readiness namespace’s
  `runtime/lab-suricata.socket`;
- the future runtime path is a new
  `<isolated-root>/attempts/<attempt-id>` namespace;
- the persistent audit path remains
  `<isolated-root>/audit/owner-once.jsonl` and is not reset or replaced;
- the original failure JSON, signed authorization, audit ledger, `.runtime-staging/`,
  frozen candidate, thresholds, six PCAPs, signed replay, trust anchors, and
  model artifacts are byte-for-byte unchanged.

If `/usr/bin/suricata -V` or native `-T` is unavailable or fails, stop and
record `READY_FOR_REVIEWED_AUTHORIZATION` as not achieved. Do not consume a
nonce or attempt activation.

## 4. Decision boundary after readiness

A successful report is only a readiness result, not G5 runtime acceptance.
The owner must make a separate reviewed decision, issue a new authorization
with a new nonce bound to a new attempt, and use the persistent audit ledger.
There is no automatic retry and no reuse of the consumed authorization.
