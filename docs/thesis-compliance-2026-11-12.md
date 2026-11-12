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
| Candidate-specific provenance record | PASS for review-only registration | `docs/candidate-9103012-lifecycle-2026-11-12.md`; candidate record binds run, SID, rule, PCAP, model, calibration, decision and baseline hashes; SID collision gate passed | Record is `PROPOSED`; no replay evidence or approval is asserted |
| Candidate-aware trusted replay signer | PARTIAL | `src/netids/candidate_replay.py`, `scripts/attest_candidate_replay.py`; revalidates immutable artifacts, enforces the pinned replay trust anchor, runs `-T`/`-r`, parses fresh EVE, excludes discovery PCAP and signs only after `verify_signed_replay_evidence()` passes | VM1 replay produced genuine evidence but failed the Normal false-positive gate, so no signed SID 9103012 attestation exists |
| Precommitted independent replay cohort | PASS for manifest integrity / BLOCKED for execution | `configs/suricata/isolated-candidate-9103012-independent-cases.json`, SHA-256 `57aa92f0a63bd2f8fe037904d0aecb2e2414031d5b9af8f08e5c9bbf73eddeba`; exact 2 Attack + 3 Normal cohort, discovery Attack-01 excluded | No third Attack capture is invented; Suricata execution remains unavailable |
| Candidate-aware owner/operator integration | PARTIAL | `scripts/approve_candidate_activation.py` and `scripts/operate_candidate_once.py`; exact candidate lineage, runtime scope, replay signature, authorization and rollback gates are enforced | Owner signing, live activation and rollback remain unperformed and unauthorized |
| New generated candidate experiment | FAIL | New run `lineage-new-generated-20261112-04` generated SID `9103012`; syntax passed and independent replay was executed | SID 9103012 was rejected: TP=2, FN=0, FP=3, TN=0, F1=0.5714 and FPR=1.0 |
| Rule syntax validation | PASS | VM1 Suricata 8.0.3 `-T` run `syntax-20261113-02`; one candidate rule loaded | Syntax PASS does not imply candidate safety |
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
| CI and local verification | PASS | Final implementation commit and exact-head GitHub Actions run are recorded in the evidence index; local suite, compileall and diff-check are rerun before delivery | CI validates code paths, not VM1 activation |
| SID 9103012 independent replay safety gate | FAIL | `data/private/sid-9103012-validation-20261113-p3/summary.tsv`, replay `replay-20261113-04`; fresh EVE hashes and five pinned PCAP hashes | All three Normal sessions alerted; candidate remains rejected |

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
