# Suricata AI IDS defense slide content

Ten main slides for a ten-minute presentation, with an opening and closing slide outside the ten-slide count. Timing includes brief transitions. Speaker notes are included under each slide.

## Opening slide — Review-only AI IDS for Suricata

**Subtitle:** Evidence-bounded anomaly analysis, protocol verification, and safe rule review

**Speaker note:** Introduce the project as a controlled research prototype. State up front that a live G5 activation has not been accepted and that the final demo uses preserved evidence unless a separately approved live path is ready.

## Slide 1 — Research problem

- Static signatures can miss behavior that depends on multiple events over time.
- ML alerts alone are hard to explain and can flag legitimate traffic.
- The project tests whether protocol evidence and frozen model output can support better human review.

**Speaker note (0:55):** Explain the tradeoff between fast signature matching and context-rich behavior analysis. This project keeps the ML and protocol evidence visible rather than claiming that one signature represents the complete Hybrid decision.

## Slide 2 — Objectives and scope

- Preserve capture, handoff, analysis, and review provenance.
- Evaluate Attack and challenging Normal sessions separately.
- Generate review-only Suricata candidates with human approval gates.
- Keep production changes outside the research acceptance path.

**Speaker note (0:55):** Scope is bounded to a laboratory. Dataset audits and historical rule comparisons retain known limitations; a missing historical Emerging Threats snapshot is not reconstructed.

## Slide 3 — Three-VM architecture

- VM1: Suricata sensor, PCAP capture, isolated candidate validation.
- VM2: controlled lab traffic source; enabled only for an approved demonstration.
- VM3: feature extraction, frozen inference, Hybrid review, ledger, and ELK.
- Separate production EVE-to-ELK visibility from experimental EVE-to-ML analysis.

**Speaker note (1:00):** Walk from controlled traffic to collection, handoff, analysis, and review. Clarify that historical ELK correlation exists, but continuous EVE-driven ML inference is not implemented.

## Slide 4 — Data collection and processing

- Capture metadata records the source and integrity checks.
- Sealed PCAPs move through a hash-verified handoff.
- Worker outputs retain run identity, feature lineage, and review status.
- Raw PCAPs and private evidence stay outside Git.

**Speaker note (1:00):** Show the evidence index and one sanitized manifest. Do not display raw payloads, private evidence, keys, or credentials.

## Slide 5 — AI and protocol features

- Frozen IF/AE anomaly model and calibration provenance.
- SYN-window and RST/handshake evidence support protocol interpretation.
- Feature extraction and inference are measured as distinct pipeline stages.
- The current frozen IF/AE evaluation did not separate the Normal sessions.

**Speaker note (1:00):** Cite the model digest from the signed manifest but explain the binary was not re-hashed in this closeout session. Historical metrics report IF/AE TP=3, FP=3, FN=0, TN=0 on the bounded holdout.

## Slide 6 — Hybrid verification

- Combine model output with unique-port, RST/RST-ACK, and handshake evidence.
- Preserve per-event provenance and replay controls.
- The bounded historical Hybrid result was TP=3, FP=0, FN=0, TN=3.
- This is a small laboratory result, not production accuracy.

**Speaker note (1:00):** Explain why the Hybrid layer remains review-only and why the sample size and environment prevent broad claims.

## Slide 7 — Candidate generation and human review

- Candidate SID 9103005 is tied to a frozen six-case evidence set.
- Candidate ID: `bfd6891a14dd3e648737e0a43d20f602d160085cefc92aa5f7fcfa8d32e0f1f6`.
- Replay attestation and independent public role pins verify.
- Candidate state remains `approved=false`, `deployable=false`, `deployed=false`.

**Speaker note (1:00):** Explain the separate Owner decision gate. The signed replay proves the historical replay envelope only; it is not a live activation authorization.

## Slide 8 — Frozen experimental results

- Three Attack sessions and three Normal sessions.
- Native holdout report: TP=3, FP=0, FN=0, TN=3.
- Baseline and candidate evidence are hash-bound.
- No result is claimed for unseen production traffic.

**Speaker note (1:00):** Show the manifest and candidate-verifier output. Distinguish the recovered G4 holdout from the later failed G5R4 runtime attempt.

## Slide 9 — Runtime safety and latency

- G5R4 is terminal FAILED; preserve its evidence and consumed nonce.
- Observer now requires per-probe tuple/flow correlation, candidate alert correlation, stats liveness, and bounded windows.
- The effective isolated config enables EVE flow events and five-second TCP timeouts.
- Native VM1 readiness and new activation/rollback remain unverified.
- Historical pipeline latency is reported separately from NOT_MEASURED runtime stages.

**Speaker note (1:00):** Be direct about the failure and the repair. Unit tests are not a live Suricata test. Do not describe historical replay as successful activation.

## Slide 10 — Demonstration and conclusion

- Fallback: show the verified frozen manifest, signed replay verification, regression tests, and historical failure boundary.
- Optional live view only after Owner approval and independent VM readiness.
- Main result: reproducible review evidence and safe candidate lifecycle code.
- Main limitation: no accepted live G5 activation or complete end-to-end runtime trace.

**Speaker note (1:00):** End with the measured scope and what remains before operational acceptance. Ask for questions without claiming project-wide acceptance.

## Closing slide — Questions

**Message:** Review-only laboratory evidence; production deployment not claimed.

**Speaker note:** Keep the evidence index open as the source for follow-up questions.
