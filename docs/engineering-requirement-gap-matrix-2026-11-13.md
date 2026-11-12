# Engineering requirement gap matrix — 2026-11-13

This is an engineering tracking artifact, not the final thesis report. It
records the state of the implementation on `feat/complete-suricata-ai-e2e` and
does not convert unit-test evidence into runtime acceptance.

| ID | Required behavior | Code path / evidence | Tests | Status | Acceptance gap |
|---|---|---|---|---|---|
| EVE-01 | Incremental JSONL consumption | `src/netids/eve_worker.py:JsonlEveReader` bounded chunk/line parsing; real VM1 snapshot SHA256 `2a8083ca1aeadad8df25bd623c41cb6c68520799be0e9d8149454b57fd1f8533` parsed locally | `tests/test_eve_worker.py` partial-line, malformed-line, large-file tests; parse-only real-EVE run accepted 27,619 events to exact EOF | INTEGRATION TESTED | Continuous VM3 deployment remains unavailable because its checkout lacks `eve_worker`; no ML inference claimed |
| EVE-02 | Rotation and duplicate handling | `JsonlEveReader` records fstat device/inode on each pending record; acknowledgements persist that source identity and offset in SQLite `source_cursor` | rotation, dedupe, restart cursor, and read/rotate/ack race tests | IMPLEMENTED / INTEGRATION_TESTED | Live multi-process rotation recovery not observed |
| EVE-03 | Bounded processing and graceful shutdown | `StreamingInferenceWorker` bounded synchronous processing, committed reader acknowledgements, SQLite crash ledger, stop event, window expiry/capacity | oversized-input, bounded-cycle, slow-consumer/restart, time-budget, retention, eviction and active-shutdown tests | IMPLEMENTED / INTEGRATION_TESTED | No live long-running Suricata load test |
| LEDGER-01 | Durable replay/audit state | Indexed SQLite event/replay tables, `(capture_run_id, sequence)` query index, compact SQL lookups, source cursor, immutable audit rows; output projection is archival-only; configurable free-space preflight/monitoring, safe low-space stop, expected-hash/schema/integrity-checked SQLite backup and no-overwrite recovery helpers | 2,000 ordinary-event ledger stress; 256 signed-Hybrid replay stress; query-plan/restart tests; free-space, backup, new-destination, wrong-hash, corrupt-backup, interrupted-publish and replay-preservation tests | CODED / INTEGRATION_TESTED | Total disk-capacity acceptance is BLOCKED; no live long-run backup/restore drill has been exercised |
| OUT-01 | Bounded output projection and recovery | Incremental append, bounded `.1` rotation, startup rebuild from ledger | retention, restart and projection-write/rotation tests | IMPLEMENTED / INTEGRATION_TESTED | Projection is not the authoritative audit store; SQLite ledger is authoritative |
| EVE-04 | Compatible EVE model inference | `FlowModelAdapter`, `suricata_eve_to_features`, `validate_feature_matrix`; VM1 read-only audit found 894 complete and 57 incomplete/non-TCP/UDP flow records | test-only RandomForest integration tests; VM1 EVE contract counts | BLOCKED | No verified CTU artifact with SHA/schema/preprocessing/threshold provenance is available; the VM3 SYN model has a different five-feature contract and the available UNSW bundles are development/calibration artifacts |
| HYB-01 | Hybrid protocol verification | `src/netids/hybrid_provenance.py` Ed25519 envelope verifier with event ID, strict integer sequence watermark, nested schema validation and persisted replay ledger; production trust anchor intentionally unprovisioned | missing-anchor, two-events-per-capture, 256 signed events, malformed nested payload, modified-payload, signature, replay, fingerprint, timestamp, boolean/invalid-sequence and restart tests | BLOCKED | No independently pinned producer key is provisioned; all ordinary/untrusted EVE telemetry remains unavailable |
| MODEL-01 | Provenance-bound decision threshold | `FlowModelAdapter.decision_threshold`, strict typed structured artifact threshold provenance | threshold default/non-default/missing/invalid/mismatch, bool/NaN/infinity, empty-field and calibration-digest tests | IMPLEMENTED / UNIT_TESTED | No verified production CTU artifact is available to execute this gate |
| EVID-01 | Structured anomaly provenance | `netids_stream_anomaly_v1` output with event/model/run hashes; parse-only real-EVE evidence is hash-linked but contains no model decisions | output provenance assertions; real-EVE reader accounting | IMPLEMENTED / INTEGRATION_TESTED | No trusted compatible model was loaded and no anomaly decision was emitted |
| ORCH-01 | One guarded laboratory entry point | `scripts/run_lab_workflow.py`, `src/netids/lab_workflow.py` one-shot smoke mode | workflow gate test | TESTED / UNIT_TESTED | One poll is explicitly not continuous runtime acceptance; candidate generation, owner approval, staging, activation and rollback are BLOCKED |
| LAT-01 | Monotonic latency instrumentation | `LatencyTrace` integrated by `run_streaming_lab_workflow` | workflow latency assertions | IMPLEMENTED / UNIT_TESTED | T0–T11 live runtime timings are not measured |
| RULE-01 | Safe rule-generation semantics | Existing `src/netids/rulegen.py` and review-only lifecycle retained | existing rule-generation/security suite | IMPLEMENTED / UNIT_TESTED | The historical SID 9103012 remains rejected; no new passing candidate was produced |
| LIFE-01 | Owner-gated isolated lifecycle | Existing `RuleLifecycle` and isolated runtime code | existing lifecycle/security suite | IMPLEMENTED / UNIT_TESTED | VM identity, real load/reload, SID alert and rollback remain BLOCKED without authorization |
| DATA-01 | UNSW/CTU frozen evidence preserved | Existing artifacts and manifests | existing dataset tests | ACCEPTED for preserved evidence | No new claim beyond existing limitations |
| DATA-02 | CIC-IDS2017 adapter/model/evaluation | `src/netids/adapters/cic.py` remains empty; audit report references `data/raw/cic-ids2017/Friday-WorkingHours-Afternoon-{DDos,PortScan}.pcap_ISCX.csv` | audit tests only | BLOCKED | The referenced raw files are absent from the authorized checkout; no adapter/training/lineage claim is made |
| REG-01 | Windows pinned-document verification | `documented_rule_recovery._git_blob` and lifecycle text hash normalize CRLF | `tests/test_recovery_signing_boundaries.py`; GitHub exact-head CI run `43319501945` | IMPLEMENTED / VERIFIED | Exact-head CI passed on `7e16f133932d03b939f49b0c5e97e20fadd8bd6a` |
| REG-02 | Full regression suite | fresh local Windows pytest on this implementation | 442 passed, 7 skipped; GitHub `dataset-and-lifecycle` 448 passed, 1 skipped, 16 subtests; `unit-handoff` 24 passed | IMPLEMENTED / VERIFIED LOCALLY AND IN CI | No remaining CI gate for the verified baseline; no test rerun was needed for this read-only audit |
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

## Runtime gates — 2026-11-13

### VM3 environment and model loading boundary

The existing `/home/tanhv/suricata-ai-venv` is present and usable: Python
3.14.4, pip 25.1.1, `netids` 0.1.0, scikit-learn 1.9.1, NumPy 2.5.4 and
joblib 1.6.0. It contains no model bundle. The deployed VM3 checkout is on
`9b93be48e1fd0cbce680c2cf704e15a2fef51743` and does not contain
`netids.eve_worker`, so no application code was installed or modified there.

The only private lab model found was the five-feature SYN-window experiment
`lab_syn_anomaly_v0_1/models.joblib`, SHA256
`206dadafc8d6cd96e21d838a52211d9b06d4a6ec541ea5c9a9ae8a6724ffbf5d`.
Available four-feature artifacts are UNSW-NB15 development/calibration files;
no trusted CTU model directory with loader metadata, preprocessing metadata and
threshold provenance was found. No model was deserialized.

### Real EVE parse-only accounting and ELK correlation

An immutable VM1 snapshot was copied to an isolated temporary path and verified
with SHA256 before parsing. The current branch reader accepted 27,619 events to
offset 155,437,470, with 239 duplicate events, 3 malformed lines, 2,371
incomplete-line observations and zero rotations in the static snapshot. Counts
were: stats 16,870; flow 3,932; mDNS 3,870; SSH 809; HTTP 740; alert 699;
fileinfo 699. This is parse-only evidence, not ML inference.

For the corresponding VM1 EVE timestamp window
`2026-11-06T10:26:10.462149Z` through `2026-11-07T01:15:05.715041Z`,
Elasticsearch returned: alert 335, fileinfo 397, flow 951, HTTP 397, SSH 82,
mDNS 671 and stats 5,409. The exact alert, fileinfo, flow, HTTP and SSH counts
match the source EVE counts; mDNS and stats differ by 12 and 3 respectively.
This establishes transport correlation with bounded indexing variance, not
perfect one-to-one accounting. No Filebeat, Suricata or ELK configuration was
changed.

### Cohort independence and offline readiness

The VM2 `fresh-holdouts-20261111` cases are not independent of SID9103012.
Their PCAP hashes exactly match the historical rejected cohort: Attack-01
`7eb27fe774c8d889480662eaaea1e68b2336cc04c943ff06be399a24e4c0bbb5`, Attack-02
`80b118068f89f0939d9a3c9ba72c977b08f95eff74a04e65b31cd548e0258f61`, Attack-03
`837dd0b52f3472ce620baf9479f7f44da7515901455f54e2fe907277648a3343`, Normal-01
`a4500b006908c26ffeed932244148c7372f2be2cb8abeb954cfe17ad3cda0fe7`, Normal-02
`aad42d5710eb1006b76b744983744f47322137b2703126537b46787e34b01aaf` and
Normal-03 `5a61ae059d8f25a2aa6bf1672f82d66c36f3e64de8d9d01dde6afca5081a2468`.
No new candidate holdout may use these cases.

VM1 Suricata 8.0.3 exposes native offline `-r` replay support and the
dedicated output-directory workflow is technically ready for a future
candidate. `tcpreplay` is absent. No offline replay, packet injection or rule
activation was executed because candidate-specific authorization and an
independent accepted cohort are still missing.

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

## Showcase deployment and live shadow gate — 2026-11-13

The exact feature source was deployed into user-owned roots on all three VMs:

`/home/tanhv/suricata-ai-showcase` on VM1 and VM3, and
`/home/kali/suricata-ai-showcase` on VM2. The deployed source commit is
`cff9ef9a2bc82c45b668797e596d915da1c0dc0b` and the verified archive SHA256 is
`c0469967f7f6b5f1e2b9fc7ba25cda08ecc674c93b3ad98dae41ec827df8ce43`.
The old `/home/tanhv/suricata-ai-code` checkout and existing private artifacts
were not overwritten.

The operator assets are in
`docs/THREE_VM_SHOWCASE_RUNBOOK_VI.md` and `scripts/demo/`. Strict SSH checks,
source deployment, status checks and the bounded Windows-to-VM3 EVE relay were
executed. The relay read VM1 EVE without changing production and delivered a
shadow file on VM3 that grew from 395 bytes to 262,539 bytes during controlled
VM2 traffic. The 128 MiB sink rotation guard is user-owned and does not parse or
modify EVE.

The VM2 low-rate Attack generator completed 24/24 probes with RST-refused
responses. The Normal generator completed 24 attempts but observed zero HTTP
200 responses because the current VM1 port-80 service is not the expected
synthetic lab service; this is demo traffic evidence, not a valid independent
Normal holdout. A new PCAP was not produced: the capture wrapper returned
`CAPTURE_BLOCKED` with exit 77 because `tcpdump` has no `cap_net_raw` capability.
The VM3 worker returned `ML_BLOCKED` with exit 77 because no verified compatible
four-feature model artifact exists. No synthetic prediction was emitted.

These gates support `VM_DEPLOYED` and partial `VM_VERIFIED` showcase status;
they do not support `SHOWCASE_READY` or `RESEARCH_ACCEPTED` until the missing
model, capture authorization, independent cohort and candidate approval gates
are completed.
