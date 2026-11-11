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

Approval must identify the exact candidate ID, SID, rule hash and run ID, and
record approver and UTC timestamp. ML scores, syntax success and replay success
never imply approval. The lifecycle API defaults to dry-run staging in a
lab-only directory. `activate=True` deliberately fails with an explicit owner
authorization error. A future activation must use an isolated Suricata config,
verify the exact rule hash and preserve the prior isolated state before any
change.

Rollback is an explicit audited transition and must be demonstrated only after
owner authorization for active isolated-lab use. No production deployment path
is introduced.

## Verification and limitations

Existing holdout replay evidence is historical acceptance evidence, not new
independent tuning evidence. Baseline-versus-augmented results remain the
documented proxy comparison: baseline 0/6 sessions and augmented 3/3 Attack,
0/3 Normal for SID 9103003. The candidate-specific result alone is not claimed
as baseline improvement without the full comparison. Novel attack coverage,
operational latency and production deployment remain unproven.
