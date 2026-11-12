# Thesis compliance and evidence matrix

This matrix is the final scope ledger for the pasted thesis requirements. It
distinguishes real evidence from implementation-only safeguards and from
requirements blocked by missing privileges, private inputs or historical
provenance.

| Requirement | Status | Evidence / reproduction | Limitation |
|---|---|---|---|
| Three-VM lab architecture | PASS | `infrastructure/vmware/` and final defense report | VM2/VM3 were unreachable during the 2026-11-12 read-only check |
| Production Suricata monitoring | PASS | EVE/Filebeat/ELK docs and Milestone 6 correlation evidence | No claim of continuous AI inference from EVE |
| PCAP feature extraction | PASS | `scripts/extract_syn_windows.py`, five-feature contract, worker tests | Batch/offline path |
| Training/calibration/test separation | PASS | UNSW v02 manifests and frozen lab calibration docs | Bounded datasets and possible feature overlap are disclosed |
| IF/AE model artifacts | PASS | Frozen model hash and stored experiment reports | Standalone six-session FPR was 1.0 |
| Hybrid protocol verification | PASS | `src/netids/hybrid_review.py`, calibration provenance and 3+3 holdouts | Laboratory observation, not production accuracy |
| New/unseen attack definition | PASS | Final report and baseline comparison report | No real-zero-day claim |
| ML-to-rule causal lineage | PASS for new review-only run | `data/private/lineage-new-generated-20261112-04/` links PCAP, features, frozen predictions, hybrid evidence, SID `9103012`, rule and metadata hashes | Historical SID 9103003 metadata remains unavailable |
| New generated candidate experiment | PARTIAL | New run `lineage-new-generated-20261112-04` generated SID `9103012`; separately validated SID `9103011` remains rejected | Additive SID 9103011 replay rejected it: FP=3 and FPR=1.0 |
| Rule syntax validation | PASS for syntax / PARTIAL for candidate safety | Fresh Suricata 8.0.3 `-T` passed for SID 9103011; offline replay is preserved | Candidate is rejected by the false-positive gate |
| Baseline versus augmented ET gap | PASS for a NEW baseline evaluation | `docs/baseline-comparison-evidence-2026-11-12.md`; six pinned PCAPs; active VM1 YAML/rules hashes; real EVE | Historical original ruleset identity remains unrecovered |
| Six-PCAP signed replay | PASS | `docs/documented-rule-recovery-2026-11-12.md`, signed attestation hash | Offline replay only |
| Isolated live activation | BLOCKED | `docs/isolated-rule-9103003-operational-acceptance-2026-11-12.md` | `tcpreplay` absent; no owner authorization; no activation attempted |
| Verified rollback after live activation | BLOCKED | Lifecycle state machine and negative tests | Cannot substitute unit tests for real runtime proof |
| Latency instrumentation | PASS | `src/netids/pipeline.py` wires `LatencyTrace` through extraction, inference, RST/port/handshake evidence, pure Hybrid decision, generation and local validation | Activation-dependent T8-T11 remain NOT MEASURED |
| Latency measurements | PARTIAL | Immutable lineage trace plus separately measured Suricata validation report | The legacy 0.023 ms value is decision-only, not full Hybrid evidence; live activation durations are absent |
| Suricata-to-EVE-to-ELK path | PASS | `docs/milestone-6-correlation-evidence-2026-11-12.md` | Correlation is event/flow evidence, not EVE-driven ML |
| EVE-driven continuous AI inference | NOT IMPLEMENTED | `scripts/infer_eve_batch.py` explicitly remains batch-only | Must not be claimed as real-time |
| UNSW evaluation | PASS with limitations | Frozen v02 reports and adapters | Feature-only/generalization limits disclosed |
| CTU-13 evaluation | PASS with limitations | Frozen cross-scenario reports | UDP recall and label ambiguity disclosed |
| CIC-IDS2017 training | NOT IMPLEMENTED | Dataset audit report | Duplicate headers/non-finite values; no trained CIC model claimed |
| Review-only safety | PASS | Lifecycle, provenance and approval tests | Deployment flags remain false |
| Security negative paths | PASS | Lifecycle, replay, wrong-host/interface, collision and stale-signature tests | Runtime activation itself remains unperformed |
| Final reporting and defense script | PASS | `docs/final-defense-report-2026-11-11.md`, checklist and demo script | Live activation section is correctly blocked |
| CI and local verification | PASS | Final run `43210304160` for `7c8f50a` completed successfully for dataset-and-lifecycle and unit-handoff; fresh local full suite was 354 passed, 4 skipped, plus compileall and diff-check | GitHub API exposes job success but not pytest stdout counts; local counts are the reproducible count for this checkout |

## Explicit non-claims

The project does not claim that SID 9103003 implements the complete Python
Hybrid detector, that the original generated RST metadata was recovered, that
the entire historical Emerging Threats ruleset missed reconnaissance, that the
system detects every zero-day attack, or that offline replay duration is live
activation latency.

## Exact remaining human actions

Only a human owner can authorize a one-time isolated activation, hold the owner
private signing credential, and provide any required package/privilege change.
Those actions remain out of scope until VM1 has a verified loopback replay
mechanism and all preflight gates pass.
