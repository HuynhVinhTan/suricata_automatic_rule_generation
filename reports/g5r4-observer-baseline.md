# G5R4 observer repair baseline manifest

Captured before source edits in the isolated repair worktree.

| Field | Baseline |
|---|---|
| Repository | `HuynhVinhTan/suricata_automatic_rule_generation` |
| PR branch | `feat/complete-suricata-ai-e2e` |
| Remote PR HEAD | `bc99275c4282381b83ddabfdd2c29c0d0f4927f8` |
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

The clean PR checkout does not contain the G5 candidate/rule file, calibration
threshold metadata, model artifact, six signed PCAP files, signed replay
attestation, owner/replay/runtime public key files, G5R4 failure report, or the
41-record owner audit. Their baseline SHA256 values therefore cannot be
independently recorded from this worktree. The supplied incident summary is
retained as context; it is not treated as a substitute for those original
artifacts. No runtime evidence file was edited or deleted. This missing input
inventory is an acceptance limitation for the full immutable-input audit.

The code pin source `src/netids/key_pins.py` and production configuration
`infrastructure/suricata/suricata.yaml` are tracked and were present at
baseline. Observer repair changes are scoped to runtime observation,
validation, failure evidence, tests and documentation; no production rule,
configuration, dataset or model file is part of the planned patch.
