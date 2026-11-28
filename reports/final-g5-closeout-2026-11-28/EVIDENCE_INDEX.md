# Evidence index

This index separates files verified in the current local session from historical evidence whose bytes remain on the lab VMs. Hashes identify artifacts; they do not imply a new runtime pass.

| Claim | Evidence | Verification | Status and scope |
|---|---|---|---|
| Five recovered frozen development and holdout artifacts are exact | `D:\suricata-ai-project-worktrees\feat-complete-suricata-ai-e2e\.runtime-staging\g4-rst-dev-20261124T075112Z-9d0b815b\` and `...\g4-holdout-20261124T084145Z-fd9f2786\` | `scripts.verify_frozen_rst_candidate` with source `c3aaa982fcb2d38b71d51ac9ae2af8a41b3e1dad`; hashes in `FROZEN_INPUT_MANIFEST.json` | PASS for local files |
| Cohort plan is available and verified | `...\g4-holdout-20261124T084145Z-fd9f2786\cohort-plan.json` | Consumed by frozen candidate verifier; SHA256 `c82bfd9c5d085f9738d79d8afa588677f4e0943d0cbe814b3064ca88925b1ef0` | PASS |
| Candidate identity and embedded baseline binding verify | `D:\suricata-ai-project-worktrees\g5r2-owner-signing\candidate.json` | `verify_frozen_candidate(candidate, candidate.baseline_comparison)` | PASS; candidate ID `bfd6891a…` |
| Signed replay attestation verifies against pinned signer | `D:\suricata-ai-project-worktrees\g5r2-owner-signing\replay-attestation.json`; `replay.pub.pem` | `verify_frozen_replay_attestation`; SHA256 `73a81eb8…` | PASS; historical replay only |
| Replay, owner, and runtime public roles are pinned and independent | `replay.pub.pem`, `owner.pub.pem`, `runtime.pub.pem` in the G5R2 package | `require_pinned_frozen_g5_role_keys` | PASS; no private key or owner authorization read |
| Frozen calibration configuration bytes match metadata | `configs/hybrid_normal_calibration.json` | SHA256 `da3b310a…`, equals frozen expected digest | PASS; separate raw calibration-decision artifact remains NOT RECOVERED |
| Six holdout outcomes in frozen evidence | Native holdout report and signed replay plan | Frozen verifier: TP=3, FP=0, FN=0, TN=3 | Historical G4 offline result, not live G5 |
| Candidate source is bound to development evidence | Development evidence, freeze, candidate | `git merge-base --is-ancestor c3aaa982… HEAD`; verifier confirms evidence source commit | PASS |
| Observer reports only probe-correlated evidence | `src/netids/isolated_suricata_runtime.py`; `tests/test_g5_probe_observer_hardening.py` | Focused suite and full suite | Code-level PASS; no real PCAP replay this session |
| Isolated config enables flow output and bounded flow end time | `src/netids/isolated_suricata_runtime.py`; `tests/test_g5_native_readiness.py` | Generated-config regression; effective config also used by native readiness validator | Offline PASS; native VM1 `-T` remains NOT RUN |
| G5R4 failure remains terminal | VM1 path `/home/tanhv/suricata-rule-review/isolated-lifecycle-9103005/attempts/g5r4` | Owner-supplied hashes listed in `FROZEN_INPUT_MANIFEST.json` | Historical evidence reported, raw files inaccessible in this local session |
| Full offline repository suite | Test output from current code commit | `PYTHONPATH=src python -m pytest -q` | 723 passed, 51 skipped |
| Exact-head GitHub Actions | [Actions run 46087222282](https://github.com/HuynhVinhTan/suricata_automatic_rule_generation/actions/runs/46087222282) | Exact head `67a4edd9e70bd2de68ca2236e14174a43053f3aa` | PASS; `unit-handoff`, `capture-boundary`, `dataset-and-lifecycle` all succeeded |
| Source-only runtime archive | `reports/releases/suricata-ai-g5-runtime-67a4edd.tar` | SHA256 `95b8d00e842a47c08ca28be368850afa9f8b42f6510dedf5e298fe3b32978c9f`; 768,000 bytes | Prepared locally from the exact CI-passing commit; not deployed |
| G5 runtime, rollback, signed acceptance | No new runtime evidence | No VM operation was performed | BLOCKED; do not infer from G5R4 or historical holdout |

## Historical evidence references

- `docs/g5-runtime-recovery-plan-2026-11-25.md` preserves the terminal failure and prohibits retry/reuse of the prior nonce.
- `docs/g5-native-readiness-procedure-2026-11-25.md` is the Owner-operated non-live VM1 readiness procedure.
- `docs/g5-frozen-rst-runtime-bridge.md` documents candidate/replay identity and signature boundaries.
- `docs/g6-latency-instrumentation.md` records historic pipeline timing evidence and the corrected observer boundary.
- `docs/final-defense-report-2026-11-11.md`, `docs/final-showcase-packet-evidence-2026-11-13.md`, and `docs/engineering-requirement-gap-matrix-2026-11-13.md` preserve prior research and integration status.

The original Word reports in `reports/` were not changed. No PCAP, model binary, private evidence file, private key, password, nonce, or authorization secret was added to Git.
