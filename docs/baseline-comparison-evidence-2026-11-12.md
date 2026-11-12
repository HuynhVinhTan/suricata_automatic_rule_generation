# New baseline-versus-augmented experiment evidence

## Provenance and scope

This newly conducted VM1 comparison is not a reconstruction of the historical
ruleset. The effective VM1 YAML and rules file were copied read-only on
2026-11-12, then used in two fresh offline Suricata 8.0.3 arms. Production
Suricata, Filebeat, EVE, interfaces and privileges were not changed.

| Artifact | Value |
|---|---|
| Run ID | `baseline-new-vm1-20261112-aef06c2` |
| Suricata | `8.0.3 RELEASE` |
| Effective YAML SHA-256 | `6224bc7d0bc04d97c4282f54a71e0736341341aa82c530fe22aed3da28814d72` |
| Enabled rule file | `/var/lib/suricata/rules/suricata.rules` via `rule-files: suricata.rules` |
| New baseline rules SHA-256 | `30d7a02cd85f7f7544231a91008a20dedbb15ff0e11ca388ac07aa8d564bf36b` |
| Baseline active unique SIDs | 53,249 |
| Augmented active unique SIDs | 53,250 |
| Candidate SID / canonical SHA-256 | `9103003` / `7182bb328ce4ed1230c6de9b20c825d458b8c224a494d6b2a60063cca5ec21df` |
| Derived report SHA-256 | `e3392fcf2e3a48c0557b5b064a50db15c47f29a6056b42363c67adf0e4babd71` |
| Private report | `data/private/baseline-new-vm1-20261112-aef06c2/report.json` |

The file contains SURICATA, GPL and ET-origin signatures. Its exact historical
feed/version identity is not established; source attribution is therefore
`NEW_VM1_COPY_2026-11-12`, not “original ET snapshot”.

## Precommitted detection definition

Before replay, the reconnaissance allow-list was frozen as every active rule in
the copied ruleset with `classtype:attempted-recon` or
`classtype:network-scan`, plus candidate SID `9103003`. The 300-SID manifest is
privately preserved at `data/private/baseline-new-vm1-20261112-aef06c2/recon-sids-20261112.txt`
with SHA-256 `80e343a0c25642834424c13f0ee4fc80845a00a3fba6679d1bc68d402e119360`.
Generic alerts were retained in EVE but not counted as reconnaissance unless
their SID was in this allow-list.

## Exact paired inputs

| Session | Label | PCAP SHA-256 |
|---|---|---|
| attack-01 | Attack | `7eb27fe774c8d889480662eaaea1e68b2336cc04c943ff06be399a24e4c0bbb5` |
| attack-02 | Attack | `80b118068f89f0939d9a3c9ba72c977b08f95eff74a04e65b31cd548e0258f61` |
| attack-03 | Attack | `837dd0b52f3472ce620baf9479f7f44da7515901455f54e2fe907277648a3343` |
| normal-01 | Normal | `a4500b006908c26ffeed932244148c7372f2be2cb8abeb954cfe17ad3cda0fe7` |
| normal-02 | Normal | `aad42d5710eb1006b76b744983744f47322137b2703126537b46787e34b01aaf` |
| normal-03 | Normal | `5a61ae059d8f25a2aa6bf1672f82d66c36f3e64de8d9d01dde6afca5081a2468` |

The harness required all six hashes, exactly three labels of each class, fresh
exclusive output directories, syntax preflight for both effective rulesets,
process timeouts, valid non-empty EVE JSON and exact baseline-union-candidate
SID identity.

## Results

| Arm | TP | FP | FN | TN | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| New baseline | 0 | 0 | 3 | 3 | 0.000 | 0.000 | 0.000 | 0.000 |
| Baseline + SID 9103003 | 3 | 0 | 0 | 3 | 1.000 | 1.000 | 1.000 | 0.000 |

This establishes that the newly copied enabled ruleset produced no alert from
the precommitted reconnaissance set on these three Attack sessions, while the
augmented candidate did. It does not prove that every historical ET rule
missed the attacks and does not generalize beyond this six-session lab.

## Reproduction

The source harness is [compare_suricata_baseline.py](../scripts/compare_suricata_baseline.py).
Raw EVE files and syntax logs remain private under the VM1 run directory; the
derived report and allow-list hash are the public evidence boundary.
