# Engineering requirement gap matrix — 2026-11-13

This is an engineering tracking artifact, not the final thesis report. It
records the state of the implementation on `feat/complete-suricata-ai-e2e` and
does not convert unit-test evidence into runtime acceptance.

| ID | Required behavior | Code path / evidence | Tests | Status | Acceptance gap |
|---|---|---|---|---|---|
| EVE-01 | Incremental JSONL consumption | `src/netids/eve_worker.py:JsonlEveReader` bounded chunk/line parsing | `tests/test_eve_worker.py` partial-line, malformed-line, large-file tests | IMPLEMENTED / UNIT_TESTED | Live Suricata stream not observed in this environment |
| EVE-02 | Rotation and duplicate handling | `JsonlEveReader` records fstat device/inode on each pending record; acknowledgements persist that source identity and offset in SQLite `source_cursor` | rotation, dedupe, restart cursor, and read/rotate/ack race tests | IMPLEMENTED / INTEGRATION_TESTED | Live multi-process rotation recovery not observed |
| EVE-03 | Bounded processing and graceful shutdown | `StreamingInferenceWorker` bounded synchronous processing, committed reader acknowledgements, SQLite crash ledger, stop event, window expiry/capacity | oversized-input, bounded-cycle, slow-consumer/restart, time-budget, retention, eviction and active-shutdown tests | IMPLEMENTED / INTEGRATION_TESTED | No live long-running Suricata load test |
| LEDGER-01 | Durable replay/audit state | Indexed SQLite event/replay tables, `(capture_run_id, sequence)` query index, compact SQL lookups, source cursor, immutable audit rows; output projection is archival-only; configurable free-space preflight/monitoring, safe low-space stop, expected-hash/schema/integrity-checked SQLite backup and no-overwrite recovery helpers | 2,000 ordinary-event ledger stress; 256 signed-Hybrid replay stress; query-plan/restart tests; free-space, backup, new-destination, wrong-hash, corrupt-backup, interrupted-publish and replay-preservation tests | CODED / INTEGRATION_TESTED | Total disk-capacity acceptance is BLOCKED; no live long-run backup/restore drill has been exercised |
| OUT-01 | Bounded output projection and recovery | Incremental append, bounded `.1` rotation, startup rebuild from ledger | retention, restart and projection-write/rotation tests | IMPLEMENTED / INTEGRATION_TESTED | Projection is not the authoritative audit store; SQLite ledger is authoritative |
| EVE-04 | Compatible EVE model inference | `FlowModelAdapter`, `suricata_eve_to_features`, `validate_feature_matrix`; VM1 read-only audit found 894 complete and 57 incomplete/non-TCP/UDP flow records | test-only RandomForest integration tests; VM1 EVE contract counts | BLOCKED | No verified CTU artifact with SHA/schema/preprocessing/threshold provenance is available; the VM3 SYN model has a different five-feature contract and the available UNSW bundles are development/calibration artifacts |
| HYB-01 | Hybrid protocol verification | `src/netids/hybrid_provenance.py` Ed25519 envelope verifier with event ID, strict integer sequence watermark, nested schema validation and persisted replay ledger; production trust anchor intentionally unprovisioned | missing-anchor, two-events-per-capture, 256 signed events, malformed nested payload, modified-payload, signature, replay, fingerprint, timestamp, boolean/invalid-sequence and restart tests | BLOCKED | No independently pinned producer key is provisioned; all ordinary/untrusted EVE telemetry remains unavailable |
| MODEL-01 | Provenance-bound decision threshold | `FlowModelAdapter.decision_threshold`, strict typed structured artifact threshold provenance | threshold default/non-default/missing/invalid/mismatch, bool/NaN/infinity, empty-field and calibration-digest tests | IMPLEMENTED / UNIT_TESTED | No verified production CTU artifact is available to execute this gate |
| EVID-01 | Structured anomaly provenance | `netids_stream_anomaly_v1` output with event/model/run hashes | output provenance assertions | IMPLEMENTED / INTEGRATION_TESTED | No live EVE evidence hash recorded |
| ORCH-01 | One guarded laboratory entry point | `scripts/run_lab_workflow.py`, `src/netids/lab_workflow.py` one-shot smoke mode | workflow gate test | TESTED / UNIT_TESTED | One poll is explicitly not continuous runtime acceptance; candidate generation, owner approval, staging, activation and rollback are BLOCKED |
| LAT-01 | Monotonic latency instrumentation | `LatencyTrace` integrated by `run_streaming_lab_workflow` | workflow latency assertions | IMPLEMENTED / UNIT_TESTED | T0–T11 live runtime timings are not measured |
| RULE-01 | Safe rule-generation semantics | Existing `src/netids/rulegen.py` and review-only lifecycle retained | existing rule-generation/security suite | IMPLEMENTED / UNIT_TESTED | The historical SID 9103012 remains rejected; no new passing candidate was produced |
| LIFE-01 | Owner-gated isolated lifecycle | Existing `RuleLifecycle` and isolated runtime code | existing lifecycle/security suite | IMPLEMENTED / UNIT_TESTED | VM identity, real load/reload, SID alert and rollback remain BLOCKED without authorization |
| DATA-01 | UNSW/CTU frozen evidence preserved | Existing artifacts and manifests | existing dataset tests | ACCEPTED for preserved evidence | No new claim beyond existing limitations |
| DATA-02 | CIC-IDS2017 adapter/model/evaluation | `src/netids/adapters/cic.py` remains empty; audit report references `data/raw/cic-ids2017/Friday-WorkingHours-Afternoon-{DDos,PortScan}.pcap_ISCX.csv` | audit tests only | BLOCKED | The referenced raw files are absent from the authorized checkout; no adapter/training/lineage claim is made |
| REG-01 | Windows pinned-document verification | `documented_rule_recovery._git_blob` and lifecycle text hash normalize CRLF | `tests/test_recovery_signing_boundaries.py`; GitHub exact-head CI run `43319501945` | IMPLEMENTED / VERIFIED | Exact-head CI passed on `7e16f133932d03b939f49b0c5e97e20fadd8bd6a` |
| REG-02 | Full regression suite | fresh local Windows pytest on this implementation | 442 passed, 7 skipped; GitHub `dataset-and-lifecycle` 440 passed, 1 skipped, 16 subtests; `unit-handoff` 24 passed | IMPLEMENTED / VERIFIED LOCALLY AND IN CI | No remaining CI gate for the verified baseline; no test rerun was needed for this read-only audit |
| VM-01 | Actual isolated Suricata activation | `src/netids/isolated_suricata_runtime.py`; VM1 read-only preflight confirmed Suricata 8.0.3 and `tcpreplay` absent | negative-path tests; VM1 `suricata -T` passed with a temporary non-production log directory | BLOCKED | Requires an approved replay mechanism, exact candidate-specific owner signing, and isolated write/reload authorization; production services remain untouched |
| VM-02 | Actual rollback and post-rollback SID proof | existing runtime rollback gates | negative-path tests | BLOCKED | No live activation was performed; tests cannot substitute for runtime evidence |

## Authoritative ledger storage policy — Option B

The SQLite `events`, `hybrid_replay`, and `source_cursor` tables are the
authoritative audit and replay state. They are append-only for this worker;
the bounded JSONL projection and `.1` rotation must never be treated as a
replacement for those records. The worker does not silently delete or compact
historical ledger rows.

Operational requirements before total-storage acceptance:

- Before starting or resuming a long run, require free space of at least the
  greater of 1 GiB or twice the current ledger size.
- Monitor free space and ledger growth at least once per processing cycle;
  alert at less than 2 GiB free or less than twice the ledger size, and stop
  ingestion before free space falls below 1 GiB or the current ledger size.
- Operators must make immutable, access-controlled backups using SQLite's
  consistent backup mechanism, record the backup SHA256 and source ledger
  size, and verify the hash before considering the backup archival.
- Recovery is: stop the worker, verify and restore the latest backup, preserve
  `hybrid_replay` and `source_cursor`, rebuild the bounded output projection
  from `events`, then resume only after the restored ledger hash and free-space
  checks pass.
- No automatic deletion, truncation, or replay-ledger rotation is authorized;
  storage monitoring, backup, archival, and recovery are operator duties.

The worker and `scripts/infer_eve_stream.py` now enforce the configured
disk-capacity checks and expose the consistent-backup/recovery helpers. Until a
live VM long-run backup/restore drill is exercised, total ledger storage remains
**BLOCKED** even though the output projection is bounded.

## Immutable historical evidence retained

Candidate SID `9103012`, candidate ID
`84ad314c885d821fb69713353134671cb355662a6effec1b890d59f38cada7e4`, source
run `lineage-new-generated-20261112-04`, and its rejected independent cohort
remain unchanged. The recorded result is TP=2, FN=0, FP=3, TN=0, precision
0.4000, recall 1.0000, F1 0.5714 and FPR 1.0000. This branch does not retune
or relabel that holdout.

## Required external actions before overall acceptance

1. Provide a trusted, version-compatible CTU flow model artifact if the
   streaming worker is to run against the frozen model rather than the test
   classifier.
2. Provide a genuinely new development cohort and independent Attack/Normal
   cohort for a new candidate; the rejected SID 9103012 cohort is immutable.
3. Authorize the exact isolated VM operation: SSH/file transfer, isolated
   directory writes, Suricata syntax/load/reload, packet replay, EVE capture,
   owner signing and rollback verification.
4. Exact-head CI is complete for `7e16f133932d03b939f49b0c5e97e20fadd8bd6a`; preserve successful run `43319501945` and its conclusion in the acceptance ledger.
5. Provision an independently pinned Hybrid producer Ed25519 public key and
   fingerprint, or keep Hybrid unavailable; no private key is requested or
   stored by this project.

Overall status for this matrix: **BLOCKED**, not complete.

## Read-only three-VM audit — 2026-11-13

All three aliases passed strict-host-key, BatchMode login with the expected
identities after Windows OpenSSH Authentication Agent recovery.

| VM | Evidence | Result |
|---|---|---|
| VM1 `192.168.10.10` | Suricata 8.0.3 and Filebeat active; production YAML SHA256 `6224bc7d0bc04d97c4282f54a71e0736341341aa82c530fe22aed3da28814d72`; active rules SHA256 `30d7a02cd85f7f7544231a91008a20dedbb15ff0e11ca388ac07aa8d564bf36b`; EVE SHA256 `276f1c469f6c8707f438134040db3c99dceef5383e6257186ae78ce871cf9d8f`; 894 complete flow records, 57 incomplete/non-TCP/UDP; `/` 57% used, 24% inodes | Read-only preflight passed; no production process or file changed |
| VM2 `192.168.10.20` | `eth1` `192.168.10.20/24`; ping VM1 2/2, 0% loss; fresh three-Attack/three-Normal holdout manifests and calibration generator manifests present; `/` 23% used, 10% inodes | Dataset inventory available; new traffic remains owner-gated |
| VM3 `192.168.10.30` | Elasticsearch HTTP 200 and Kibana HTTP 302; historical `suricata-eve-*` and `suricata-ai-summary` indices present; no active AI worker; Python 3.14.4 with no pip; `/` 16% used, 7% inodes | ELK reachable; sustained inference is blocked by missing trusted compatible runtime artifact/environment |

The VM1 syntax check initially encountered the expected unprivileged log-dir
permission error. Re-running `suricata -T` with a temporary non-production log
directory returned `syntax_rc=0` and reported that the configuration loaded
successfully. `tcpreplay` is absent on VM1 and was not installed.
