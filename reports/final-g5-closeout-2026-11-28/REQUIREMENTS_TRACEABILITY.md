# Requirements traceability

## Research and system scope

| Requirement | Implementation and evidence | Result | Limitation |
|---|---|---|---|
| Detect network behavior beyond manually authored signatures | Three-VM capture, handoff, worker, Hybrid evidence, and Suricata lifecycle exist in repository; see `docs/final-defense-report-2026-11-11.md` | Implemented for bounded laboratory workflows | Not a production accuracy claim |
| Dataset preparation and quality controls | Existing CTU/UNSW/CIC audits and `docs/unresolved-requirements-2026-11-11.md` | Prior offline work preserved | CIC adapter/training blocked by duplicate headers/non-finite values; largest CTU contradiction audit remains resource-limited |
| Historical Emerging Threats rule comparison | New copied baseline is documented in `docs/baseline-comparison-evidence-2026-11-12.md` | New baseline evidence exists | Does not recover the unavailable historical Emerging Threats snapshot |
| Independent model evaluation | G4 six-case holdout evidence: 3 Attack and 3 Normal; candidate results TP=3, FP=0, FN=0, TN=3 | PASS within that frozen lab cohort | Small sample and bounded environment; no generalization claim |
| Standalone IF/AE model separation | Existing research report reports TP=3, FP=3, FN=0, TN=0 | Not achieved | Both models flagged Normal sessions; Hybrid remains the useful bounded decision layer |
| Model and feature provenance | Frozen metadata binds model/calibration digests and feature lineage | Provenance recorded | Model bytes could not be rehashed in this local session; raw calibration-decision file remains unavailable |
| Hybrid protocol evidence | Python Hybrid aggregates ports, RST/RST-ACK, handshake failures and frozen model output | Implemented for accepted historical lab evidence | No continuously running EVE-to-ML production worker; trust and runtime gates remain separate |
| Candidate generation and provenance | Candidate SID 9103005, candidate ID `bfd6891a…`, signed replay attestation verifies | PASS as review-only evidence | `approved=false`, `deployable=false`, `deployed=false` |
| Human review and approval | Separate owner authorization tools and pinned public role keys | Fail-closed workflow exists | No new approval created; candidate remains review-only |
| Native Suricata validation | Existing historical Suricata 8.0.3 holdout report | Historical syntax/replay evidence | Current effective observer config has not been run through VM1 native `-T` |
| Probe-correlated runtime acceptance | Observer now requires exact flow tuples/IDs and candidate alert correlation during a bounded window; isolated config enables event types and five-second TCP timeouts | Offline code and regression tests pass | No VM1/real-PCAP telemetry run proves the corrected contract in Suricata 8.0.3 |
| Runtime activation and rollback | `scripts/operate_frozen_rst_once.py` enforces one-shot, isolated, rollback, audit, deadline and production-snapshot gates | Code exists; G5R4 terminal status preserved | No fresh authorization, activation, or rollback is claimed |
| Production safety | Current patch changes only isolated runtime config generation and tests; production YAML/rules are untouched | No production change made by this work | Live VM state was not independently inspected in this session |
| EVE and ELK visibility | Historical VM1/VM3 EVE-to-ELK correlation in `docs/engineering-requirement-gap-matrix-2026-11-13.md` | Historical integration evidence | Current ELK/Kibana availability and dashboard state were not tested |
| Continuous EVE-to-ML operation | Existing report explicitly distinguishes production EVE-to-ELK from continuous ML | Not implemented | It must not be presented as an operational capability |
| G6 latency | Existing pipeline timing and 607-record EVE-to-ledger sample are separated from NOT_MEASURED runtime stages | Report prepared | No complete current T0-T11 trace, no cross-host synchronization proof |

## Dataset and research scope notes

- **CTU-13:** preserved dataset audits exist. The largest duplicate/contradiction audit was previously blocked by available disk; no missing result is inferred.
- **CIC-IDS2017:** raw CSV quality issues include duplicate headers and non-finite rates. No adapter or new model training was introduced near the defense deadline.
- **Emerging Threats:** the candidate-specific comparison uses a copied ruleset with SHA256 `30d7a02c…`; it is not evidence for an unrecovered historical ET snapshot.
- **Independent holdout:** the recovered G4 cohort has three Attack and three Normal sessions with TP=3, FP=0, FN=0, TN=3 in its signed native report. The G5R4 runtime attempt is a separate failed experiment.
- **EVE-to-ML:** existing production EVE-to-ELK visibility is distinct from continuous ML inference; the latter is not implemented.
- **Thesis scope:** no original thesis or signed research approval document was present in the authorized local workspace. This matrix follows the current repository acceptance documents and the Owner's task brief, not an unseen thesis source.

## Defense claims to avoid

Do not say the project achieved production deployment, continuous EVE-driven ML inference, production accuracy, live G5 activation, live rollback acceptance, or a passing G5 signed runtime. Do not describe the historical holdout replay as the G5R4 runtime attempt.
