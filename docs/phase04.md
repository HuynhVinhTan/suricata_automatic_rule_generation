# Phase 4: PCAP batch automation safety

## Scope and invariants

Phase 4 hardens the existing VM1 sender / VM3 consumer handoff. It does not
enable systemd timers, change production Suricata or Filebeat configuration,
alter the EVE -> Filebeat -> Logstash -> Elasticsearch path, change frozen
models/checksums/thresholds, or deploy candidate rules. Candidate rules remain
review-only. `send` and `consume` stay dry-run unless `--execute` is supplied.

## Batch and recovery behavior

- `--all-ready` validates existing bundle receipts and processes the first 10
  pending runs in sorted run-ID order. Valid historical receipts do not use
  the limit. A malformed, mismatched, or orphan receipt fails the invocation;
  it is not silently treated as completed.
- If the consumer finds output from a successful worker run but no completion
  receipt, it verifies the bundle/run identity, worker-summary checksum and
  schema, frozen-model provenance, feature and prediction provenance, and
  review-only fields. It then retries the optional summary publication and
  writes a new exclusive `.done.json` receipt only after publication succeeds.
  The worker is not rerun and existing artifacts are not overwritten.
- An incomplete or failed existing output is preserved and blocks reprocessing
  for operator inspection. Failed transfers retain any `.partial` evidence;
  automation does not remove incomplete remote transfers.
- Elasticsearch `409` is successful only if an explicit GET confirms the
  expected stable ID, index, and exact safe summary source. A missing, altered,
  unsafe, or unverifiable document is a failure.

## Offline evidence

Targeted regression command:

```powershell
python -m pytest -q tests\test_worker.py tests\test_phase3_pcap_handoff.py
```

Result: **129 passed, 1 skipped**. Coverage includes more than 10 historical
bundles, the 10-pending limit, invalid sent/done receipts, recovery after an
Elasticsearch outage without a second worker run, completed-output provenance
and review safety, matching/conflicting Elasticsearch documents, and
idempotent receipt handling.

Full unit suite (excluding the locked official test module):

```powershell
python -m pytest -q tests --ignore=tests\test_unsw_v02_official_test.py
```

Result: **214 passed, 1 skipped, 16 subtests passed**. The official test was
not run.

These are local unit tests using temporary files and mocked HTTP/SSH boundaries.
They do not establish live VM connectivity, Elasticsearch availability,
systemd/timer behavior, or production acceptance. Timers remain disabled.