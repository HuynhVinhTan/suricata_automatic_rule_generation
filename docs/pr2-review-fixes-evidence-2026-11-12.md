# PR #2 review-fix evidence — dataset audit and fail-closed rule lifecycle

Date: 2026-11-12. Branch: `feat/dataset-audit-rule-lifecycle`.

## Dataset audit

`src/netids/dataset_audit.py` now reads source bytes with strict UTF-8, hashes
the unchanged source, preserves duplicate header positions, reports equal and
unequal duplicate-column values, and removes its temporary SQLite database in
all exit paths. When the configured disk budget is unavailable it continues a
bounded streaming pass and reports `PARTIAL`; exact duplicate and contradictory
label results are `null`, never fabricated. Malformed rows are counted and
invalid encodings raise `UnicodeDecodeError`. No official UNSW test was rerun.

## Lifecycle gates

`RuleLifecycle` rejects historical blocked SIDs and configured collisions,
requires all four provenance hashes, binds authenticated syntax plus attack and
Normal replay evidence to the exact candidate, and preserves the distinction
between the RST telemetry proxy and the full Python hybrid. Approval is an
explicit, independently verified authorization record with candidate, run, SID,
rule hash, isolated environment, operation, identity, UTC window, and replay
protection. Audit records include sequence, previous-record hash and record hash;
this is an append-only local log, not a claim of external tamper-proof storage.

Staging is dry-run by default and only accepts a canonical path below the
configured isolated root. Explicit isolated activation validates syntax, writes
atomically, preserves prior state, and supports rollback. No production path,
privilege, Suricata configuration, EVE path, or rule set was changed.

## Existing Milestone 6 evidence retained

The six pre-existing correlation envelopes remain the source of truth and are
not regenerated here:

| run_id | PCAP SHA-256 | EVE events | flows | review / SID |
|---|---|---:|---:|---|
| worker-attack-holdout-01-20261111 | `7eb27fe774c8d889480662eaaea1e68b2336cc04c943ff06be399a24e4c0bbb5` | 32 | 24 | needs_review / 9103003 |
| worker-attack-holdout-02-20261111 | `80b118068f89f0939d9a3c9ba72c977b08f95eff74a04e65b31cd548e0258f61` | 32 | 24 | needs_review / 9103003 |
| worker-attack-holdout-03-20261111 | `837dd0b52f3472ce620baf9479f7f44da7515901455f54e2fe907277648a3343` | 32 | 24 | needs_review / 9103003 |
| worker-normal-holdout-01-20261111 | `a4500b006908c26ffeed932244148c7372f2be2cb8abeb954cfe17ad3cda0fe7` | 72 | 24 | no_candidate / 9103003 |
| worker-normal-holdout-02-20261111 | `aad42d5710eb1006b76b744983744f47322137b2703126537b46787e34b01aaf` | 69 | 24 | no_candidate / 9103003 |
| worker-normal-holdout-03-20261111 | `5a61ae059d8f25a2aa6bf1672f82d66c36f3e64de8d9d01dde6afca5081a2468` | 66 | 24 | no_candidate / 9103003 |

Totals are 303 matching EVE events and 144 matching flows. The complete
provenance, manifest/model/calibration hashes, EVE hashes, AI-summary IDs and
classification values are in
`artifacts/milestones-4-6-acceptance-20261112/correlation-envelopes.json`.
Those records are event-verified, preserve native EVE JSON, and remain
review-only (`approved=false`, `deployable=false`, `deployed=false`).

## Reviewer security hardening — new PR #2 follow-up

Subsequent to commit `c4aca26`, the lifecycle now verifies domain-separated
HMAC-SHA256 attestations before accepting replay evidence or owner approval.
The replay signer and owner signer use independent keys supplied by private,
trusted operator processes, not by rule artifacts or committed files.
Caller-supplied verification callbacks and unsigned replay booleans cannot
authorize progression. A signed authorization binds candidate identity, run,
SID, rule SHA256, isolated root, exact operation, nonce and UTC expiration.
Nonce reuse is rejected in the audit ledger.

Sensitive lifecycle transitions can no longer be performed with a generic
`transition()` call. Audit writes verify the existing hash chain, use an
exclusive local lock and call `fsync`. A local hash chain is not a trusted
external audit anchor and does not prove resilience against administrative
tampering.

The isolated activation interface now requires a runtime adapter to validate
syntax, activate the exact rule, and verify the running ruleset before assigning
`ACTIVE_IN_ISOLATED_LAB`. Failed activation must verify rollback; an
unverified runtime rollback is reported FAILED rather than successful.
Unit tests use synthetic keys and a mocked runtime. **No trusted owner-signing
service, authenticated replay signer or real isolated Suricata runtime adapter
has yet been demonstrated.** These production-like gates remain open.
Do not treat mock runtime tests as actual isolated Suricata activation.

## Acceptance correction

**Milestone 6 remains FULLY ACCEPTED for the six bounded lab experiments**, as
documented in `docs/milestone-6-correlation-evidence-2026-11-12.md`.
The six derived worker summaries were already indexed and verified in the
existing `suricata-ai-summary` index by commit `c86b3d6`.
This PR does not re-index them, nor does it undo that acceptance.

**Phase 3 active isolated-lab installation remains NOT ACCEPTED / PENDING
EXPLICIT OWNER APPROVAL and independently verified runtime evidence.**
No production or lab rule was activated by the reviewer.
Full CI and Word visual QA remain separate acceptance gates.
