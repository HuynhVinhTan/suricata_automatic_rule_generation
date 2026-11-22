# Master Phase 1 Acceptance — 2026-11-23

Status is maintained from observed command output and preserved evidence. A
runtime PASS is never inferred from offline fixtures, CI, or documentation.

## Executive verdict

`MASTER_PHASE1_PARTIAL`

G0 has a reviewed test correction and successful exact-head CI. The VM2
read-only preflight passed, but the one approved deployment attempt rolled
back safely after a restricted-shell verification error. Deployment pointer
activation, fresh capture, live EVE correlation,
lab key provisioning, independent 3+3 holdout evaluation, and native VM1
isolated replay remain unexecuted pending their separately scoped approvals
and genuine evidence.

## Acceptance matrix

| Gate | Status | Evidence / blocker |
|---|---|---|
| G0 Code/security QA | PARTIAL | Commit `00bacb39c2b791f0324cb7bbf80a30246a6d950e` changes only `tests/test_attack_capture_process.py`; focused Windows run: 90 passed, 3 skipped. POSIX process test is queued in Linux CI run [45078027779](https://github.com/HuynhVinhTan/suricata_automatic_rule_generation/actions/runs/45078027779). Full Windows run: 471 passed, 20 failed, 19 skipped; failures are environment/data-audit related and are not attributed to this patch. |
| G1 VM2 source release | BLOCKED | Archive SHA matched locally and remotely; new release and all four script hashes verified. Final reporting hit missing restricted-shell `cat`; the guarded trap restored `current` and `source-commit.txt` to `386ae2df…`; the new release remains preserved but inactive. |
| G2 packet | BLOCKED | No new capture authorization or execution. Historical normal-only PCAP is not attack evidence. |
| G2 EVE | BLOCKED | No fresh packet evidence or separately approved VM1/VM3 read-only correlation. |
| G3 Hybrid LAB_DEMO_ONLY | BLOCKED | Offline envelope/replay tests exist; live producer key provisioning and independent VM3 pinning are not authorized or performed. |
| G4 candidate safety | BLOCKED | Frozen five-feature code path is present, but no genuine disjoint 3 Attack + 3 Normal holdout is available in this run. |
| G5 isolated Suricata/rollback | NOT_MEASURED | No candidate has reached accepted REVIEW_ONLY status and no candidate-specific VM1 approval exists. |
| G6 final QA/handoff | PARTIAL | This record and measured preflight/CI references exist; final runtime evidence is pending. |

## Observed provenance

- Feature branch: `feat/complete-suricata-ai-e2e`.
- Reviewed source before the test correction: `cda528af6a6face46f8d6815897bf8786258abcf`.
- Current pushed source: `00bacb39c2b791f0324cb7bbf80a30246a6d950e`.
- G1 approved archive source: `b6e8ad999979090a37bd1273d544dc3d89d9abd4`.
- G1 archive SHA256: `fec58b25b2763b5d1468f73a583e72eacd301b06b0dee0b96ec1dbce285f53ee`.
- PR: [#5](https://github.com/HuynhVinhTan/suricata_automatic_rule_generation/pull/5), open, draft, base `dev`.
- VM2 preflight: host `kali`, user `kali`, interface `eth1`, address `192.168.10.20/24`.
- VM2 historical source metadata: `386ae2dfdd39d66ce9f14928bf9eabcf014d7f8d`.
- Historical deployed script hashes observed during preflight:
  - `vm2-capture-session.sh`: `09fff68b53647adbf31f1d6edbcbd0f05149157c5e2971e66ef09094a86b7610`
  - `vm2-generate-attack.sh`: `fa3a5e839559f4d2523d9e92de87e77e9ea3fdaa63f1c66011dd97b02b44714d`
  - `verify_attack_evidence.py`: `b93a3c9d76d5b642c2366a6b6317115218cf63f58f8838e03cb49757a4ce2530`

## Approval ledger

| Scope | Approval | Actual execution | Result |
|---|---|---|---|
| Local source/test inspection and edit | Not required | Worktree inspection, focused tests, source-only test correction | Completed |
| Git commit/push to feature branch | Authorized by task | Pushed `00bacb39…` | Completed; no force push or merge |
| VM2 read-only preflight | Previously authorized narrow scope | One SSH read-only command; no sudo/capture/generator | Completed |
| VM2 source deployment | Granted for exact `b6e8ad9…` | Archive transferred and verified; release extracted; guarded pointer update rolled back after restricted-shell verification failure | G1 blocked; no active source change |
| Fresh VM2 capture | Not granted | Not executed | Deferred |
| VM3 trust provisioning / VM1 isolated runtime | Not granted | Not executed | Deferred |

## Required next approvals

1. Approve VM2-only deployment of the exact CI-reviewed commit, including a
   versioned release archive, archive hash verification, current symlink update,
   source metadata, and rollback to `386ae2df…`; VM1 and VM3 are excluded.
2. After G1, approve exactly one VM2 capture using `eth1`, the authorized lab
   pair, ports `18100–18123`, 24 attempts, 120 seconds, 5,000 packets, snaplen
   96, and no retry.
3. Only after packet PASS, separately approve lab-only key provisioning and
   VM3 public-key pinning.
4. Only after G4 acceptance, separately approve the exact candidate SID/hash
   and isolated VM1 native replay/rollback.

## Limitations

The Windows full-suite result is not an acceptance PASS: the configured
environment reported zero free space for the worker ledger preflight, and one
dataset-audit assertion failed. POSIX process tests were skipped locally and
must be accepted only from Linux CI output. No live packet, EVE, signature,
candidate, native Suricata, or rollback claim is made here.

## G1 deployment evidence

The approved archive was created from the exact approved commit and its local
and VM2 SHA256 both matched. The verified inactive release contains these
hashes:

| File | SHA256 |
|---|---|
| `scripts/demo/vm2-capture-session.sh` | `09608890bc9d74e44c115212c1d9f5bf6745246ab6b2d0755c9b588139d1c25f` |
| `scripts/demo/vm2-capture-supervisor.sh` | `f7f70f364fbfd41ec270539eccc04b75c73cadc1a5d90e816abc038d9f88e4b0` |
| `scripts/demo/vm2-generate-attack.sh` | `fa3a5e839559f4d2523d9e92de87e77e9ea3fdaa63f1c66011dd97b02b44714d` |
| `scripts/verify_attack_evidence.py` | `b93a3c9d76d5b642c2366a6b6317115218cf63f58f8838e03cb49757a4ce2530` |

The active pointer remains the historical release and the historical source
metadata remains unchanged. No G2 command was started. Completing G1 now
requires a separately approved pointer-activation/verification retry using
absolute command paths compatible with VM2's restricted SSH shell.
