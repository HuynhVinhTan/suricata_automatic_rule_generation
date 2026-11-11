# Suricata rule lifecycle acceptance

## Decision

The code-level review-only lifecycle is accepted for candidate creation,
provenance validation, explicit state transitions, dry-run staging and
rollback. Active isolated-lab installation is **PENDING OWNER APPROVAL** and
was not attempted. Production Suricata, Filebeat, YAML, privileges and rules
were not changed.

## State machine

```text
PROPOSED -> VALIDATING -> VALIDATED_FOR_REVIEW -> AWAITING_APPROVAL
                                      |                    |
                                   REJECTED       APPROVED_FOR_ISOLATED_LAB
                                                           |
                                             STAGED_IN_ISOLATED_LAB
                                                           |
                                              ACTIVE_IN_ISOLATED_LAB
                                                           |
                                                    ROLLED_BACK
```

Every transition is explicit and append-only audited. Invalid transitions,
missing provenance, SID collisions, modified rule hashes, unsafe paths and
activation without a separate owner authorization fail closed.

## Real evidence

The existing validated candidate is SID `9103003`, rule SHA-256
`7182bb328ce4ed1230c6de9b20c825d458b8c224a494d6b2a60063cca5ec21df`.
It is a review-only RST telemetry proxy: isolated Suricata 8.0.3 replay
detected 3/3 Attack and 0/3 Normal holdouts. It does not implement the full
Python hybrid. Rejected historical SIDs remain reserved and cannot be reused.

Candidate generation remains deterministic and bound to run ID, PCAP SHA-256,
model SHA-256, calibration provenance, SID and rule SHA-256. A failed evidence
gate returns a rejection reason or no-candidate result; it does not create an
unsafe rule.

## Human approval and staging

Approval must identify the exact candidate ID, SID, rule hash, run ID,
isolated root and operation, with an independently authorized approver, UTC
validity window and nonce. The lifecycle verifies a domain-separated
HMAC-SHA256 owner attestation using a private verification key, separate from
the trusted replay-attestation key. The keys are never committed to Git and the
review artifact cannot mint its own authorization. Unsigned booleans and
caller-controlled verifier callbacks are rejected. A separate privileged
operator process must actually authenticate the replay and owner before
signing any record.

The API defaults to dry-run staging without writing rule files. The optional
`activate=True` path is code-level only: it requires a verified owner record
scoped specifically to activation and an independently trusted isolated
Suricata runtime adapter providing syntax validation, activation, post-
activation verification, rollback and post-rollback verification. Writing a
`.rules` file alone must not set ACTIVE. Failed or unverifiable runtime
activation cannot be counted as successful; attempted rollback is recorded.

The existing unit tests use synthetic test-only signing keys and a mock
runtime. **They do not demonstrate that a real Suricata process loaded or
deactivated any rule.** A live isolated runtime adapter, operator approval and
exact evidence remain pending. Original production review flags stay false;
no production deployment path is introduced.

## Verification and limitations

Existing holdout replay evidence is historical acceptance evidence, not new
independent tuning evidence. Baseline-versus-augmented results remain the
documented proxy comparison: baseline 0/6 sessions and augmented 3/3 Attack,
0/3 Normal for SID 9103003. The candidate-specific result alone is not claimed
as baseline improvement without the full comparison. Novel attack coverage,
operational latency and production deployment remain unproven.


## Executable review-only registration from real worker artifacts

The existing worker already produces ml-generated.rules and
ml-generated.metadata.json. The new src/netids/lifecycle_integration.py
reads them through the established backend.rule_handoff._read_artifacts()
validator, and binds the proposal to the SHA256 of an owner-pinned
calibration file and an owner-pinned baseline rules snapshot.
Blocked and conflicting SIDs are rejected. Only a PROPOSED candidate
is recorded in the private local audit ledger.

PowerShell example (replace paths and hashes with independently verified
values; keep private artifacts and the audit outside Git):

    python -m scripts.register_generated_rule_review --artifact-dir "data/private/verified-worker-artifacts/RUN_ID" --run-id "RUN_ID" --calibration-manifest "configs/hybrid_normal_calibration.json" --expected-calibration-sha256 "YOUR_VERIFIED_64_HEX_SHA" --baseline-rules "data/private/verified-baseline.rules" --expected-baseline-sha256 "YOUR_VERIFIED_64_HEX_SHA" --audit-path "data/private/lifecycle/RUN_ID-audit.jsonl" --isolated-root "data/private/isolated-lab"

This command does NOT write into the Suricata rules directory, transfer
candidate files to VM1, sign replay evidence, approve a rule, or reload
Suricata. A separate trusted replay attester must verify actual Suricata
8.0.3 syntax and independent Attack/Normal replay before signing an
attestation. Separately, a human owner must authorize an exact,
short-lived isolated-lab action using a protected signing service.

No trusted real Suricata runtime adapter or private signing services
have been installed by this PR. Mocked runtime tests are NOT real
Suricata activation evidence. The remaining gate is explicit owner
approval plus real isolated activation and verified rollback, with CI.
