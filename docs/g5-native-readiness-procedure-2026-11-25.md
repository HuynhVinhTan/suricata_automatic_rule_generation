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
ATTEMPT_ID=g5r1
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

The short attempt ID is intentional: on the reviewed VM1 layout the future
runtime socket pathname is 101 encoded bytes, below Linux's 107-byte pathname
limit. Check the exact bytes before running the validator:

```bash
python3 - "$ROOT" "$ATTEMPT_ID" <<'PY'
import os
import pathlib
import sys

socket_path = pathlib.Path(sys.argv[1]) / "attempts" / sys.argv[2] / "runtime" / "lab-suricata.socket"
length = len(os.fsencode(str(socket_path)))
assert length <= 107, (length, socket_path)
print(f"future socket pathname bytes: {length}")
PY
```

The validator repeats this check, validates the unused attempt namespace before
any lifecycle or authorization work, and refuses to truncate the ID or fall
back to a production socket.

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
- the generated native YAML begins with `%YAML 1.1` followed by `---`;
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

## 5. Root operator and privilege-separated runtime procedure

The live operator is a root-owned local process on VM1. Before it can create an
attempt namespace or append the persistent ledger, verify the invoking shell has
EUID 0. The operator never runs as `suricata-g5`, never changes production
configuration or rules, and never invokes `systemctl`:

```bash
sudo -i
test "$(id -u)" = 0
cd /home/tanhv/suricata-rule-review/repository
PYTHONPATH=src python3 scripts/operate_frozen_rst_once.py \
  --candidate /home/tanhv/g5-signed/sid9103005-candidate.json \
  --replay /home/tanhv/g5-signed/sid9103005-replay-attestation.json \
  --owner-authorization /home/tanhv/g5-signed/sid9103005-owner-authorization.json \
  --replay-public /home/tanhv/.config/suricata-ai/g5-replay-9103005/replay.pub.pem \
  --owner-public /home/tanhv/.config/suricata-ai/g5-owner-9103005/owner.pub.pem \
  --runtime-public /home/tanhv/.config/suricata-ai/g5-runtime-9103005/runtime.pub.pem \
  --production-yaml /etc/suricata/suricata.yaml \
  --production-rules /var/lib/suricata/rules/suricata.rules \
  --isolated-yaml "$ROOT/isolated.yaml" \
  --isolated-root "$ROOT" \
  --attempt-id "$ATTEMPT_ID" \
  --audit-path "$ROOT/audit/owner-once.jsonl" \
  --runtime-private /home/tanhv/.config/suricata-ai/g5-runtime-9103005/runtime.pem \
  --evidence-output "$ROOT/attempts/$ATTEMPT_ID/runtime-evidence.json" \
  --failure-output "$ROOT/attempts/$ATTEMPT_ID/runtime-failure.json" \
  --probe A1=/ABSOLUTE/VERIFIED/A1.pcap \
  --probe A2=/ABSOLUTE/VERIFIED/A2.pcap \
  --probe A3=/ABSOLUTE/VERIFIED/A3.pcap \
  --probe N1=/ABSOLUTE/VERIFIED/N1.pcap \
  --probe N2=/ABSOLUTE/VERIFIED/N2.pcap \
  --probe N3=/ABSOLUTE/VERIFIED/N3.pcap
```

The operator validates the dedicated account before launch: user and group
`suricata-g5`, UID 999, GID 982, `nologin` shell, no home, and no supplementary
root group. Suricata is started by the root operator with
`--user=suricata-g5 --group=suricata-g5`; only that child drops privileges.
The operator verifies `/proc/<pid>/status` after startup and before socket
readiness or replay: every UID is 999, every GID is 982, the process is alive,
and `Groups:` contains no GID 0. A mismatch terminates the child, verifies
termination, preserves diagnostics, and blocks replay.

The attempt ACL is narrow and is applied with argument-array `setfacl` calls:

- attempt root and rules directory: execute only;
- runtime and logs directories: write and execute only;
- effective YAML and each explicitly referenced classification, reference,
  threshold, include, or rule file: read only;
- `active.rules`: read only, reapplied after baseline, activation, and rollback
  atomic replacement;
- audit, owner authorization, production paths, and unrelated attempts: no ACL.

The persistent audit ledger remains root:root with mode `0600` in a root-only
directory. It is append-only and is never chmodded, chowned, deleted, or
replaced. After the child is verified stopped, the operator removes only ACL
entries belonging to the current attempt. If process termination or ACL cleanup
cannot be verified, it reports failure, preserves diagnostics and evidence, and
does not retry.
