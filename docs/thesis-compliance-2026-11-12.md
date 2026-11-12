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
| ML-to-rule causal lineage | PARTIAL | `pipeline.py`, `rulegen.py`, `worker.py`, provenance tests | Historical SID metadata unavailable; documented recovery is separate |
| New generated candidate experiment | PARTIAL | Existing generated SID 9103001 is preserved as rejected; review-only registration is tested | No new candidate is represented as authentic without private input execution |
| Rule syntax validation | PASS | Suricata `-T` replay evidence and lifecycle tests | Candidate-specific syntax, not full hybrid semantics |
| Baseline versus augmented ET gap | PARTIAL | `docs/suricata-baseline-comparison-2026-11-12.md` and harness | Historical ET snapshot/private PCAPs unavailable; whole-ET metric not measured |
| Six-PCAP signed replay | PASS | `docs/documented-rule-recovery-2026-11-12.md`, signed attestation hash | Offline replay only |
| Isolated live activation | BLOCKED | `docs/isolated-rule-9103003-operational-acceptance-2026-11-12.md` | `tcpreplay` absent; no owner authorization; no activation attempted |
| Verified rollback after live activation | BLOCKED | Lifecycle state machine and negative tests | Cannot substitute unit tests for real runtime proof |
| Latency instrumentation | PASS for available stages | `src/netids/latency.py`, `tests/test_latency.py` | Activation-dependent T8-T11 remain NOT MEASURED |
| Latency measurements | PARTIAL | Existing reports intentionally omit offline replay as live latency | A new end-to-end live run is blocked |
| Suricata-to-EVE-to-ELK path | PASS | `docs/milestone-6-correlation-evidence-2026-11-12.md` | Correlation is event/flow evidence, not EVE-driven ML |
| EVE-driven continuous AI inference | NOT IMPLEMENTED | `scripts/infer_eve_batch.py` explicitly remains batch-only | Must not be claimed as real-time |
| UNSW evaluation | PASS with limitations | Frozen v02 reports and adapters | Feature-only/generalization limits disclosed |
| CTU-13 evaluation | PASS with limitations | Frozen cross-scenario reports | UDP recall and label ambiguity disclosed |
| CIC-IDS2017 training | NOT IMPLEMENTED | Dataset audit report | Duplicate headers/non-finite values; no trained CIC model claimed |
| Review-only safety | PASS | Lifecycle, provenance and approval tests | Deployment flags remain false |
| Security negative paths | PASS | Lifecycle, replay, wrong-host/interface, collision and stale-signature tests | Runtime activation itself remains unperformed |
| Final reporting and defense script | PASS | `docs/final-defense-report-2026-11-11.md`, checklist and demo script | Live activation section is correctly blocked |
| CI and local verification | PASS | 344 passed, 4 skipped; focused 32 passed; compileall and diff-check clean | Final CI push verification requires network/remote delivery |

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
