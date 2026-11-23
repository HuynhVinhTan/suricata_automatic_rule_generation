# G2–G6 offline closeout — 2026-11-23

This record covers repository-only work on `feat/complete-suricata-ai-e2e`.
No SSH, sudo, VM mutation, key provisioning, packet capture, generator traffic,
Suricata runtime, production reload, or live retry was performed for this
closeout.

## Status matrix

| Stage | STATUS | ACTUAL EVIDENCE | SOURCE/ARTIFACT HASH | TEST/CI RESULT | RUNTIME RESULT | REMAINING BLOCKER |
|---|---|---|---|---|---|---|
| G0 source, tests, CI, security QA | PASS | Validated code head `a32ab93987f4c53fe548d28d7dd4ca535006feb5`; later commits only synchronize this report; PR #5 remains OPEN/DRAFT | G2 launcher `712de52f02f80a8cab549b4d286bff38c6c674dd68e3714b46bc2c69582910a9`; G3 demo `6d3e2e8b6d35166d30b5124c06e11a51602b7da8711251995a88d495fef72b47`; G3 CLI `56f7b5aa89c005da96baa92a263f2bf269738dadc243f66c25bcdc87488812a5`; G5 harness `c4561f7d7c7c3bc27a0916a8d0e87c24557212354ff7fc4d539e0ab45ca27e36` | Targeted 46 passed/5 skipped; full 512 passed/37 skipped; compileall and diff-check passed; exact-head CI [45121531656](https://github.com/HuynhVinhTan/suricata_automatic_rule_generation/actions/runs/45121531656) and final report-sync CI [45121721822](https://github.com/HuynhVinhTan/suricata_automatic_rule_generation/actions/runs/45121721822) passed all three jobs | No runtime claim | Live gates remain separately blocked |
| G1 release/source provenance | PASS | Previously accepted reviewed release/source provenance is preserved; no release files were changed here | Existing reviewed release constants and prior evidence | Existing accepted CI/evidence | No new deployment | None for this offline closeout |
| G2 live packet capture | BLOCKED | Failed run `g2-live-attack-20261123T051225Z-29e0e0f0da9147ee` is preserved; no PCAP, manifest, or packets resulted | Failed run seed `20261123051225`; no new evidence hash | Launcher regression suite remains passing | Not run; no retry | One fresh owner-authorized VM1 `ens33` capture plus one VM2 invocation |
| G3 Hybrid Ed25519 producer/trust/replay | OFFLINE_READY | Canonical signed record binds run/event/sequence/time/source-PCAP/manifest metadata; SQLite ledger is durable and exclusive | Hashes recorded after final commit; no keys are stored | 10 dedicated positive/negative tests pass offline | VM2 key provisioning and VM3 pinning not performed | Explicit runtime approval, independently compared fingerprint, and public-key transfer only |
| G4 independent ML evidence and safe candidate | DATA_PENDING | Frozen five-feature SYN/PCAP code and safety path remain; no private frozen bundle or six disjoint runtime sessions is in either checkout | Historical claimed model digest is not re-used as current verification | Existing offline G4/lifecycle tests remain in the full suite | No six-session runtime evidence | Actual frozen model bytes, threshold lineage, and 3 Attack + 3 Normal sessions |
| G5 native isolated Suricata validation and rollback | OFFLINE_READY | Native `-T`/`-r` comparison harness and candidate lifecycle are preserved; rejected SID 9103012 is now fail-closed | Candidate/config/PCAP hashes are checked at runtime; no candidate accepted here | Targeted harness tests pass offline | No Suricata runtime or rollback performed | Accepted G4 candidate-specific SID/rule hash and separate owner approval |
| G6 three-VM operation, ELK/demo, latency, final reporting | BLOCKED | Existing four-feature showcase documentation remains explicitly distinct from frozen five-feature G4 | No new live evidence | Repository tests only | No three-VM demonstration in this closeout | G2–G5 accepted runtime evidence and owner-authorized demo |

## G3 trust boundary and offline CLI

The installed entry points are `g3-lab-provision-key`, `g3-lab-sign`, and
`g3-lab-verify`. The reviewed source wrappers remain at
`scripts/g3_lab_provision_key.py`, `scripts/g3_lab_sign.py`, and
`scripts/g3_lab_verify.py`; they delegate to the installed `netids` package,
so execution does not depend on the checkout being accidentally on `sys.path`.

The LAB_DEMO_ONLY envelope requires `schema_version`, `run_id`, `event_id`,
non-negative `sequence`, UTC timestamp, VM2/VM3 identities, artifact SHA256,
source PCAP SHA256, manifest SHA256, review-only manifest metadata, and
review-only evidence. Every field is signed canonically. VM3 checks the
independently supplied pinned public-key fingerprint before signature
verification and records nonce, run, event, sequence, envelope, artifact,
PCAP and manifest hashes in the SQLite `verified_envelopes` table under
`BEGIN IMMEDIATE`, `synchronous=FULL`, and a unique nonce/run/event/envelope.

The private key is generated and retained only on VM2. Only the public PEM and
the independently compared fingerprint may later be transferred to VM3. No
live key, fingerprint, or private evidence was created or installed here.

## G4 and G5 boundaries

The required frozen features remain:
`syn_count`, `unique_dst_ports`, `repeated_probes`,
`median_inter_syn_seconds`, and `syn_rate_per_second`. The dedicated G2
capture is not one of the required six G4 sessions. G4 requires three
independent Attack and three independent Normal runs, distinct run IDs,
disjoint provenance, per-run PCAP/manifest hashes, and zero Normal/control
candidate false alerts. The repository contains no current frozen model bytes
or private six-session evidence, so neither model-hash verification nor a new
candidate is claimed.

G5 remains an offline-ready native Suricata harness. It requires a genuinely
accepted G4 candidate before any candidate-specific runtime operation. The
historically rejected SID 9103012 is rejected before Suricata execution. The
`--case` value is one quoted argv value containing `PCAP|SHA256`; the parser
uses the final delimiter, so a literal `|` in a path is not a shell pipeline.
No `tcpreplay`, host-loopback injection, production configuration, or
production rule activation is part of this closeout.

## Notion-ready factual summary

- G2 safety patch remains accepted; the failed wrapper run is preserved and no
  live retry occurred.
- G3 is implemented and offline-ready with an installed package path,
  Ed25519 pinned verification, signed lineage fields, and SQLite replay
  protection; runtime trust provisioning remains pending.
- G4 is data-pending because the frozen model bytes and six independent
  packet-backed sessions are not present in the checkout.
- G5 is offline-ready and fail-closed for SID 9103012, but candidate-specific
  runtime acceptance is pending G4.
- G6 is blocked pending genuine G2–G5 runtime evidence.
