# G5R4 observer repair baseline manifest

Captured before source edits in the isolated repair worktree.

| Field | Baseline |
|---|---|
| Repository | `HuynhVinhTan/suricata_automatic_rule_generation` |
| PR branch | `feat/complete-suricata-ai-e2e` |
| Baseline HEAD | `9c888bee00ec7d70368d2f0ec61d4ae17f609a6d` |
| Remote PR HEAD at task start | `9c888bee00ec7d70368d2f0ec61d4ae17f609a6d` |
| Working branch | `codex/g5r4-observer-repair` |
| Worktree | `D:\suricata-ai-project-worktrees\g5r4-observer-repair` |
| Git status before edits | clean; tracking `origin/feat/complete-suricata-ai-e2e` |
| PR | #5, OPEN / DRAFT, base `dev` |
| CodeGraph | `.codegraph/` absent; no CodeGraph index used |

## Source audit hashes

SHA256 values below are for the exact file contents at baseline commit
`bc99275c4282381b83ddabfdd2c29c0d0f4927f8`.

| File | SHA256 |
|---|---|
| `src/netids/isolated_suricata_runtime.py` | `3e4d0d8a25a78a72b13a394bba70f985c9487d91a78fef12cfa2f086cb0ee1f7` |
| `src/netids/latency.py` | `b0bda16e04e4f7917fa37ea4e119cc2376b2d803ec0bc211f2bc560355d60d63` |
| `src/netids/rule_lifecycle.py` | `33aff1bdd748783b4bb1c8c4d2080617a975df99a0029a3502154fc7be5b504b` |
| `scripts/operate_frozen_rst_once.py` | `d9d3798e468ecbfe9266bce981ff3d543441d88446e567f7fce4562504c25453` |
| `src/netids/g5_frozen_candidate.py` | `56f1c32f048c22b3c81e2ce2c5ca81e89e6ccb9b7ce2713df8959849976708d3` |
| `src/netids/key_pins.py` | `69dafcf078b35d3ab5a3a4d6ab6dba1c0198a930e29666c74a8bcd68a8295717` |
| `tests/test_isolated_runtime_preflight.py` | `d307a655816f68604ba79bca1d5d75fe083a378ecac7fcc860df1fd94816cad3` |
| `tests/test_latency.py` | `775e22ada8ca7c5fd89dbc4ade584fe50882984f326a3174ce873c005be30e0d` |
| `tests/test_runtime_orchestration_contract.py` | `185c9428f3b6b0ee94d87f545f4f00cad93223d3c448c87b786de1a965c36ded` |
| `tests/test_rule_lifecycle.py` | `dfaab0928b6da1c6ee0f67a9ceae1e1575c4f259ae4dc6784483ed33fa5be4e1` |
| `tests/test_rule_lifecycle_integration.py` | `b03eff666705200599bf52a91c2c379d6eb469c61d69a241b0db0c66a955741f` |
| `tests/test_g5_frozen_candidate_bridge.py` | `7e869988e98aac8b2becdc8d5b7a434cfab6dd939d4e758db39a9b4c1aa09c0e` |
| `docs/g6-latency-instrumentation.md` | `314bb3efdd57c82e2ac2d747a74b3645d40088e759505f256fab877b5cd947b8` |
| `infrastructure/suricata/suricata.yaml` | `6224bc7d0bc04d97c4282f54a71e0736341341aa82c530fe22aed3da28814d72` |

## Frozen runtime inputs

An offline bounded search recovered `candidate.json` and
`replay-attestation.json` in `g5r2-owner-signing`. Their SHA256 values are
`5a2c3e2b6c65eb056b08d047a897690eaef252c4715f5f94952c630a7eac8161` and
`73a81eb8ef2c99a324ce1f720125d8b1f12eef50c0cd6b390efc5defc78f4989`.
Candidate shape, replay signature, and pinned public-key verification passed.
The frozen identity matches SID 9103005, candidate ID
`bfd6891a14dd3e648737e0a43d20f602d160085cefc92aa5f7fcfa8d32e0f1f6`, rule
file hash `171c1405ad7019feebf588039a1479ceb70a3596b607e1ff122bb87667babb49`,
freeze hash `74ce643d782d525e83910138b32218bc69e8d97a6908e725f71dbbeab0fd9bd4`,
and cohort hash `443b42478b3bfbc0d66433fc5e582433426962fe54427278b584a5e5e859efaa`.
The referenced model exists at `data/private/lab-models/lab_syn_anomaly_v0_1/models.joblib`
and matches its frozen model hash. The runtime public key pin also matches.

The six original PCAPs, exact G5R4 owner authorization archive, threshold and
calibration source, runtime failure report, diagnostics, EVE, Suricata logs,
owner-once log, and 41-record audit were not found in the bounded known roots.
The previously supplied hashes for failure report, diagnostics, EVE, and audit
did not match any available files there. These missing authoritative inputs
keep artifact-dependent acceptance tasks blocked. No private key bytes were
read or hashed, and no runtime evidence file was edited or deleted.

The code pin source `src/netids/key_pins.py` and production configuration
`infrastructure/suricata/suricata.yaml` are tracked and were present at
baseline. Observer repair changes are scoped to runtime observation,
validation, failure evidence, tests and documentation; no production rule,
configuration, dataset or model file is part of the planned patch.
