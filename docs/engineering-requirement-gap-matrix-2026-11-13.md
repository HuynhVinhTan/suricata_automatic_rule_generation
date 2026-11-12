# Engineering requirement gap matrix — 2026-11-13

This is an engineering tracking artifact, not the final thesis report. It
records the state of the implementation on `feat/complete-suricata-ai-e2e` and
does not convert unit-test evidence into runtime acceptance.

| ID | Required behavior | Code path / evidence | Tests | Status | Acceptance gap |
|---|---|---|---|---|---|
| EVE-01 | Incremental JSONL consumption | `src/netids/eve_worker.py:JsonlEveReader` bounded chunk/line parsing | `tests/test_eve_worker.py` partial-line, malformed-line, large-file tests | IMPLEMENTED / UNIT_TESTED | Live Suricata stream not observed in this environment |
| EVE-02 | Rotation and duplicate handling | `JsonlEveReader.read_available()` identity/offset/dedupe | rotation and dedupe tests | IMPLEMENTED / UNIT_TESTED | Multi-process checkpoint recovery is not implemented |
| EVE-03 | Bounded processing and graceful shutdown | `StreamingInferenceWorker` bounded synchronous processing, committed reader acknowledgements, SQLite crash ledger, stop event, window expiry/capacity | oversized-input, bounded-cycle, slow-consumer/restart, time-budget, retention, eviction and active-shutdown tests | IMPLEMENTED / INTEGRATION_TESTED | No live long-running Suricata load test |
| EVE-04 | Compatible EVE model inference | `FlowModelAdapter`, `suricata_eve_to_features`, `validate_feature_matrix` | test-only RandomForest integration tests | BLOCKED | No verified CTU artifact with SHA/schema/preprocessing/threshold provenance is available; synthetic model is test-only |
| HYB-01 | Hybrid protocol verification | `src/netids/hybrid_provenance.py` Ed25519 envelope verifier with event ID, sequence policy and persisted replay ledger; production trust anchor intentionally unprovisioned | missing-anchor, two-events-per-capture, modified-payload, signature, replay, fingerprint and timestamp tests | BLOCKED | No independently pinned producer key is provisioned; all ordinary/untrusted EVE telemetry remains unavailable |
| MODEL-01 | Provenance-bound decision threshold | `FlowModelAdapter.decision_threshold`, artifact metadata threshold provenance | threshold default/non-default/missing/invalid/mismatch tests | IMPLEMENTED / UNIT_TESTED | No verified production CTU artifact is available to execute this gate |
| EVID-01 | Structured anomaly provenance | `netids_stream_anomaly_v1` output with event/model/run hashes | output provenance assertions | IMPLEMENTED / INTEGRATION_TESTED | No live EVE evidence hash recorded |
| ORCH-01 | One guarded laboratory entry point | `scripts/run_lab_workflow.py`, `src/netids/lab_workflow.py` one-shot smoke mode | workflow gate test | TESTED / UNIT_TESTED | One poll is explicitly not continuous runtime acceptance; candidate generation, owner approval, staging, activation and rollback are BLOCKED |
| LAT-01 | Monotonic latency instrumentation | `LatencyTrace` integrated by `run_streaming_lab_workflow` | workflow latency assertions | IMPLEMENTED / UNIT_TESTED | T0–T11 live runtime timings are not measured |
| RULE-01 | Safe rule-generation semantics | Existing `src/netids/rulegen.py` and review-only lifecycle retained | existing rule-generation/security suite | IMPLEMENTED / UNIT_TESTED | The historical SID 9103012 remains rejected; no new passing candidate was produced |
| LIFE-01 | Owner-gated isolated lifecycle | Existing `RuleLifecycle` and isolated runtime code | existing lifecycle/security suite | IMPLEMENTED / UNIT_TESTED | VM identity, real load/reload, SID alert and rollback remain BLOCKED without authorization |
| DATA-01 | UNSW/CTU frozen evidence preserved | Existing artifacts and manifests | existing dataset tests | ACCEPTED for preserved evidence | No new claim beyond existing limitations |
| DATA-02 | CIC-IDS2017 adapter/model/evaluation | `src/netids/adapters/cic.py` remains empty; audit report references `data/raw/cic-ids2017/Friday-WorkingHours-Afternoon-{DDos,PortScan}.pcap_ISCX.csv` | audit tests only | BLOCKED | The referenced raw files are absent from the authorized checkout; no adapter/training/lineage claim is made |
| REG-01 | Windows pinned-document verification | `documented_rule_recovery._git_blob` and lifecycle text hash normalize CRLF | `tests/test_recovery_signing_boundaries.py` | IMPLEMENTED / UNIT_TESTED | Exact-head CI still required |
| REG-02 | Full regression suite | fresh local pytest on this implementation | 414 passed, 7 skipped | IMPLEMENTED / VERIFIED LOCALLY | Exact-head CI still required |
| VM-01 | Actual isolated Suricata activation | `src/netids/isolated_suricata_runtime.py` | negative-path tests | BLOCKED | Requires exact VM/interface, `tcpreplay`, owner signing and write/reload authorization |
| VM-02 | Actual rollback and post-rollback SID proof | existing runtime rollback gates | negative-path tests | BLOCKED | No live activation was performed; tests cannot substitute for runtime evidence |

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
4. Run exact-head CI and preserve its URL/conclusion in the acceptance ledger.
5. Provision an independently pinned Hybrid producer Ed25519 public key and
   fingerprint, or keep Hybrid unavailable; no private key is requested or
   stored by this project.

Overall status for this matrix: **BLOCKED**, not complete.
