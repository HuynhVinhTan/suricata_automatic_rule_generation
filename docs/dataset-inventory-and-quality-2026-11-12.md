# Dataset inventory and quality audit

## Scope

This audit is read-only. It hashes and streams the local raw files; it does not
rewrite source data or rerun consumed official tests. The repository contains
raw UNSW-NB15, CIC-IDS2017 and CTU-13 files under `data/raw/`; `datasets/` is
absent. Private lab PCAPs, manifests, EVE replays and SYN-window CSVs remain
under `data/private/` and are not committed.

## Raw dataset identity

| Dataset/file | Bytes | Records | SHA-256 | Role / finding |
|---|---:|---:|---|---|
| UNSW training-set.csv | 32,293,018 | 175,341 | `bec7dd5e...0648fa` | Four-feature flow development source |
| UNSW testing-set.csv | 15,380,800 | 82,332 raw / 72,513 TCP+UDP | `734fe664...c0a559` | Consumed frozen official evaluation; do not rerun |
| CIC Friday DDoS CSV | 77,123,859 | 225,745 | `6ff1580f...b411ee` | BENIGN 97,718; DDoS 128,027; rate NaN/Inf present |
| CIC Friday PortScan CSV | 76,906,168 | 286,467 | `ca1824c5...e269e99b` | BENIGN 127,537; PortScan 158,930; rate NaN/Inf present |
| CTU capture20110815-2 | 17,766,203 | 129,832 | `ef5c9ed6...f78a02c` | Flow labels include Background, Normal and Botnet families |
| CTU capture20110817 | 285,841,002 | 2,087,508 | `c8de257b...8178bab` | Largest file; streaming-only audit required |
| CTU capture20110818-2 | 14,596,615 | 107,251 | `cee542d4...736428` | Flow labels include Background, Normal and Botnet families |
| CTU capture20110819 | 44,718,958 | 325,471 | `1098f0ad...dd9f2e` | Flow labels include Background, Normal and Botnet families |

The complete hashes are in the generated audit output when sufficient disk is
available. The profiler is `scripts/phase04_01_data_quality.py` and uses
`src/netids/dataset_audit.py`; it streams CSV rows and uses temporary SQLite
only after checking free disk. During this run, the large CTU SQLite audit was
blocked by approximately 206 MB remaining space; source files were untouched.

## Quality findings

- UNSW has 45 columns, binary `label` (`0`/`1`) and `attack_cat`. The selected
  raw fields are `dur`, packet counts and byte counts. The audit found 298
  contradictory labels for identical selected five-field vectors in training
  and 129 in the raw testing file. This is feature-vector ambiguity, not proof
  of shared sessions.
- CIC has 79 columns and a normalized duplicate `Fwd Header Length` name. The
  two local files contain non-finite `Flow Bytes/s` and `Flow Packets/s` values;
  no CIC model was trained in this repository. The empty `src/netids/adapters/cic.py`
  remains intentionally unimplemented.
- CTU uses 15-column `.binetflow` records and slash-delimited `StartTime` values.
  The adapter maps labels to `Normal`, `Botnet` and `Background`; Background is
  not automatically treated as Normal. Botnet is not Port Scanning.
- Exact duplicate and contradictory-feature checks are available in the
  profiler. The large CTU duplicate check is marked blocked until temporary
  disk is available; no result is fabricated.

## Suitability

| Intended use | Verdict | Reason |
|---|---|---|
| UNSW four-feature supervised flow ML | CONDITIONAL | Adapter and frozen lineage exist, but feature-vector overlap and feature-only split limitations remain |
| CTU cross-scenario flow evaluation | CONDITIONAL | Existing frozen report is reusable; labels and background policy are explicit, UDP recall is low |
| CIC model training | FAIL | Non-finite rates, duplicate normalized headers and no verified adapter/training lineage |
| Frozen five-feature lab PCAP worker | PASS in bounded lab | Separate Normal-trained IF/AE artifacts, six holdout manifests and existing correlation evidence |
| Production Suricata rule validation | CONDITIONAL | Only isolated replay evidence is accepted; no production reload or deployment is permitted |

No CIC model or cross-dataset equivalence is claimed. No raw dataset was
cleaned, relabeled or uploaded.
