# Final G5 acceptance and defense closeout

## Decision

The frozen candidate inputs and signed replay package verify locally, and the probe observer has a scoped offline correction with passing tests. Runtime acceptance remains blocked: the VM-side PCAP/model bytes, native Suricata readiness, a fresh Owner authorization, and a new isolated run were not available or authorized in this session. The candidate remains review-only. No production activation is claimed.

PR #5 remains OPEN/DRAFT. The source correction is committed as `67a4edd9e70bd2de68ca2236e14174a43053f3aa`; exact-head CI run `46087222282` passed all three jobs. The source-only runtime archive is `reports/releases/suricata-ai-g5-runtime-67a4edd.tar`, SHA256 `95b8d00e842a47c08ca28be368850afa9f8b42f6510dedf5e298fe3b32978c9f`, size 768,000 bytes. The package manifest identifies that reviewed runtime source revision. A later documentation-only closeout revision may change repository HEAD without changing the package source identity.

## Verified results

- Frozen SID 9103005 candidate ID: `bfd6891a14dd3e648737e0a43d20f602d160085cefc92aa5f7fcfa8d32e0f1f6`.
- Candidate JSON SHA256: `5a2c3e2b6c65eb056b08d047a897690eaef252c4715f5f94952c630a7eac8161`.
- Replay attestation SHA256: `73a81eb8ef2c99a324ce1f720125d8b1f12eef50c0cd6b390efc5defc78f4989`; signature and pinned public role keys verified.
- Frozen evidence verifier: PASS; the six-case native holdout reports TP=3, FP=0, FN=0, TN=3. This is frozen historical offline evidence, not a live G5 result.
- Local calibration configuration SHA256: `da3b310aa6d0492f80a7e00138bf922a4ae287e380f847327760c63f0217a7d9`, matching its frozen digest. The raw calibration-decision artifact remains unrecovered.
- Observer correction: effective isolated configuration now guarantees EVE `alert`, `flow`, and `stats` event types and sets TCP state timeouts to five seconds. Production configuration is not modified.
- Focused suite: 17 passed. Full suite: 723 passed, 51 skipped. Compileall and `git diff --check` passed.

## System, method, and results

The research system has three roles. VM1 runs Suricata and captures/seals traffic; VM2 generates controlled lab traffic when approved; VM3 receives PCAPs, extracts features, runs frozen IF/AE inference and Hybrid review, records provenance, and exposes selected summaries through ELK. Production Suricata EVE-to-ELK visibility and experimental EVE-to-ML processing are separate paths. Continuous EVE-driven ML inference is not implemented.

The analysis combines frozen model output with SYN/RST protocol evidence, destination-port diversity, and handshake observations. The available six-session report shows IF/AE consensus TP=3, FP=3, FN=0, TN=0, while the bounded Python Hybrid result is TP=3, FP=0, FN=0, TN=3. The G4 frozen SID 9103005 native holdout also reports 3 Attack true positives and 3 Normal true negatives. These small lab results do not estimate production accuracy.

The signed candidate binds SID 9103005, its canonical rule and complete rule file, freeze and cohort hashes, baseline evidence, and the six case identities. Candidate and replay signatures verify against pinned public roles. The candidate remains unapproved and undeployed. The baseline comparison is a new copied ruleset result; it does not recreate the historical Emerging Threats snapshot.

G5R4 is a separate terminal failed runtime attempt. Its reported flow records were emitted at shutdown, and no active Attack probe completed. The current observer requires each exact PCAP flow tuple and flow ID, a post-replay counter delta, candidate alert correlation, and a bounded observation period. The offline correction enables EVE flow records and short TCP flow timeouts in generated isolated configuration. Current native readiness, fresh in-window probe evidence, activation, rollback, and signed acceptance are not available.

The available latency measurements cover historical feature extraction, inference, a narrow legacy Hybrid decision call, candidate generation, local artifact validation, and same-host EVE-to-ledger processing. Capture through handoff, a complete current worker trace, owner approval, isolated activation, rollback, and post-rollback probes are either missing or `NOT_MEASURED`; see the stage table.

## Safety, limitations, and conclusion

This closeout did not contact a VM or perform runtime, authorization, replay, signing, or nonce work. The only implementation change alters generated isolated configuration; it does not edit production rules/configuration, the frozen candidate, model, threshold, PCAP, or historical evidence. No private key material was read or hashed. Historical G5R4 remains FAILED, its nonce remains consumed, and no retry is authorized.

Research limitations include the small holdout, standalone IF/AE false positives, incomplete large-file CTU audit, CIC-IDS2017 quality issues, unavailable historical Emerging Threats snapshot, unverified local model bytes, and the absence of continuous EVE-to-ML inference. The original thesis/approval document was not present for this audit. These gaps prevent full project acceptance.

The defensible conclusion is that the repository contains reproducible review-only candidate and lifecycle code with verified frozen holdout evidence and a newly tested observer correction. It is not ready to claim live G5 runtime acceptance or production deployment. The evidence package and fallback defense content are prepared for Owner review.

## Acceptance matrix

| Task | Status | Evidence and command | Limitation |
|---|---|---|---|
| 01 Baseline and source audit | BLOCKED | Frozen verifier passed with recovered G4 artifacts; candidate/replay signature and key pins verified; source commit `c3aaa982fcb2d38b71d51ac9ae2af8a41b3e1dad` is an ancestor of the reviewed source | Six PCAP bytes, model bytes, baseline rules bytes, fresh owner authorization, and VM-side historical artifacts were not independently re-hashed here |
| 02 Real-input probe-observation contract | BLOCKED | `tests/test_g5_probe_observer_hardening.py`, `tests/test_g5_native_readiness.py`; 17 focused tests passed | No native Suricata 8.0.3 `-T` or real-PCAP in-window observer validation; historical flow events were emitted at shutdown |
| 03 Previously accepted group | PASS* | Prior code/offline acceptance stated in Owner prompt | Original task label and evidence were not supplied for revalidation |
| 04 Previously accepted group | PASS* | Prior code/offline acceptance stated in Owner prompt | Original task label and evidence were not supplied for revalidation |
| 05 Previously accepted group | PASS* | Prior code/offline acceptance stated in Owner prompt | Original task label and evidence were not supplied for revalidation |
| 06 Previously accepted group | PASS* | Prior code/offline acceptance stated in Owner prompt | Original task label and evidence were not supplied for revalidation |
| 07 Previously accepted group | PASS* | Prior code/offline acceptance stated in Owner prompt | Original task label and evidence were not supplied for revalidation |
| 08 Immutable-input/security audit | BLOCKED | Exact local hashes and signatures are indexed in `FROZEN_INPUT_MANIFEST.json`; working-tree source change is isolated to observer configuration and test | VM before/after hashes and complete evidence ledger continuity were unavailable |
| 09 Previously accepted group | PASS* | Prior code/offline acceptance stated in Owner prompt | Original task label and evidence were not supplied for revalidation |
| 10 Immutable release package | PASS | `RELEASE_MANIFEST.json` records package hash, source revision, file list, dependencies, and reproduction instructions | Local package preparation only; no VM copy or deployment |
| 11 VM1 deployment and readiness | BLOCKED | Owner-operated readiness procedure remains in `docs/g5-native-readiness-procedure-2026-11-25.md` | No authenticated VM session, native `-T`, or verified VM identity/storage/timer state in this session |
| 12 Fresh attempt and Owner authorization | BLOCKED | No new authorization or nonce created | Requires a separate explicit Owner decision |
| 13 Active verification | BLOCKED | No activation performed | Requires Task 11 readiness and fresh authorization |
| 14 Mandatory rollback | BLOCKED | No new attempt performed | No rollback evidence may be inferred from historical G5R4 |
| 15 Signed evidence and safety acceptance | BLOCKED | Historical G5R4 remains terminal FAILED | No fresh signed runtime evidence or verified audit continuation |
| 16 G6 latency | PASS | `G6_LATENCY_REPORT.md` and `G6_LATENCY_TABLE.csv` separate measured historical pipeline stages from NOT_MEASURED stages | No complete current G5 T0–T11 trace; no new runtime timing |
| 17 Requirements and research scope audit | BLOCKED | `REQUIREMENTS_TRACEABILITY.md` maps repository evidence, datasets, model, evaluation, lifecycle, production safety, and ELK | Original thesis/research approval document was not present in the authorized workspace |
| 18 Final report and evidence index | PASS | This closeout set and `EVIDENCE_INDEX.md`; older Word reports are preserved unchanged | The Word authoring runtime was unavailable, so a separate `.docx` was not produced |
| 19 Defense slides and demonstration | BLOCKED | `DEFENSE_SLIDE_CONTENT.md`, `DEMO_RUNBOOK.md`, and `DEFENSE_QA.md` are prepared for a fallback evidence demo | Live VM/ELK walkthrough and screenshots were not validated; no live runtime acceptance is claimed |

`PASS*` means the Owner’s master prompt reports prior code/offline acceptance; the original task names and evidence were not independently reconstructed in this run.

## Final flags

```text
PHASE_1_AND_PHASE_2_COMPLETE=FALSE
PHASE_3_RUNTIME_ACCEPTED=FALSE
FINAL_REPORT_READY=TRUE
DEFENSE_DEMO_READY=FALSE
ALL_19_TASKS_ACCEPTED=FALSE
PROJECT_FINAL_ACCEPTANCE=FALSE
```

The final report package is ready for review. Operational acceptance and the live defense demo remain blocked by the stated VM and Owner authorization gates.
