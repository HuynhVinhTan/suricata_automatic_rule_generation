# Security and limitations

## Safety boundary followed

- No SSH, VM operation, Suricata command, packet replay, activation, rollback, signing, authorization, or nonce action was performed.
- No private PEM or SSH key, passphrase, credential, owner authorization, or runtime secret was read, displayed, hashed, copied, or transferred.
- Only candidate/replay evidence and public role-key files were read from the G5R2 signing package. The G5R4 directory was not opened for private authorization content.
- No production Suricata configuration, rule file, service, timer, or capture/handoff service was changed.
- No PCAP, model binary, or private VM evidence was added to the repository.
- The original G5R4 attempt remains terminal FAILED. Its nonce is consumed and cannot be reused.

## Observer correction

The observer requires flow tuples and flow IDs correlated to each exact frozen PCAP, candidate alerts tied to the expected flow, a post-replay stats delta, bounded monotonic deadlines, delayed-alert handling, and explicit outcomes. The effective isolated configuration now turns on the EVE `alert`, `flow`, and `stats` types and bounds TCP state timeouts to five seconds. These edits apply to generated isolated runtime configuration only. Production configuration and the candidate rule are unchanged.

The correction has unit and offline regression coverage. It still needs a native Suricata 8.0.3 syntax check and evidence from the real PCAPs to establish that flow events arrive during the probe window. Do not treat the corrected source or synthetic tests as live readiness.

## Evidence and provenance limits

- The candidate envelope, signed replay, public pins, recovered G4 artifacts, cohort plan, and local calibration configuration were verified in this session.
- PCAP SHA256 values are bound by the verified signed replay attestation, but the six PCAP bytes were not re-read from VM1 in this session.
- The expected model digest and size are known from the supplied evidence; VM3 model bytes were unavailable locally and were not substituted or retrained.
- The calibration config is present locally and matches its digest. The raw calibration-decision evidence remains missing.
- Baseline rules digest is bound in the candidate/comparison evidence; the original baseline rules bytes were not re-hashed locally.
- G5R4 failure, EVE, log, diagnostics, and audit hashes are supplied historical references; their VM files were not accessible to verify here.
- The accepted holdout is a six-session controlled-lab result only. It does not establish production accuracy, Hybrid equivalence, or generalization.
- Existing repository reports identify CIC-IDS2017 adapter quality issues, unfinished CTU large-file audit, unavailable historical ET snapshot, and no continuous EVE-to-ML service.
- Current production state, VM identity, storage, Suricata version, timers, and ELK availability were not checked in this session.

## Runtime authorization boundary

The Master Prompt explicitly says it is not authorization to activate a new candidate. Tasks 12-15 remain blocked until earlier readiness gates pass and the Owner separately approves the exact release, candidate, scope, deadline, rollback, and expected evidence. Any future attempt requires a new unused attempt namespace, a fresh authorization and nonce, and a one-shot procedure. Do not retry G5R4 or reuse its authorization.
