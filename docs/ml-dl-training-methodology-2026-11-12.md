# ML and DL training methodology

## UNSW-NB15

The frozen supervised contract is four transformed flow features:
`protocol_tcp`, `duration_log`, `packets_log` and `bytes_log`. The source
adapter accepts TCP/UDP, maps `label` 0 to Normal and 1 to Attack, and derives
packet/byte totals before `log1p`. The group split is frozen by exact equality
of all four transformed values: development 102,305, validation 20,462 and
calibration 20,462. Its manifest is
`artifacts/experiments/unsw_group_split_v02/manifest.json`; the split hash is
`313b9014...fc16127`.

Calibration used 7,578 Normal rows and a 0.01 FPR budget without attack labels.
The RF candidate `RF_leaf5` was selected by validation average precision and
has frozen model hash `8ecd9403...d844d30`. The official test artifact is
`artifacts/experiments/unsw_v02_official_test_v01/report.json`; its consumed
TCP/UDP cohort is 72,513 rows, RF recall 0.7889, F1 0.8724 and FPR 0.0201.
The report records 28,102 exact four-feature matches between official test and
training vectors (38.7544%). This proves identical feature values only; it does
not prove shared network sessions, hosts or timestamps. Feature-group
disjointness also does not prove host/time independence.

The official test is consumed and is not rerun. Reproducibility is limited to
reading the stored report and hashes.

## CTU-13

`src/netids/adapters/ctu.py` maps `Dur`, `TotPkts` and `TotBytes` with
`log1p`, adds `protocol_tcp`, validates finite non-negative numeric values and
parses timestamps. Labels are explicitly `Normal`, `Botnet` and `Background`;
Background remains unclassified rather than being silently made Normal. The
frozen v0.2 report is
`artifacts/reports/ctu13_s5_to_s9_rf_v0_2.json`, using model hash
`dc727edd...f44b62a` and policy hash `4715d7d0...58aed`.

It reports 3,736 training and 152,978 evaluation records, recall 0.2450, F1
0.3920 and FPR 0.0204. TCP recall is 0.5136; UDP recall is 0.0431. The low
UDP recall and enriched positive prevalence are limitations, not tuning targets.
The evaluation is cross-scenario evidence, not zero-day proof, and is not
reused for retuning.

## CIC-IDS2017

Two Friday CSVs are present: DDoS and PortScan. Initial profiling found
duplicate normalized headers and non-finite rate values. `src/netids/adapters/cic.py`
is empty and no completed CIC training artifact was verified. Therefore no CIC
adapter, model, independent evaluation or cross-dataset metric is claimed.
The appropriate next step is a separately reviewed schema-normalization and
label-policy experiment; it must not alter frozen UNSW or lab PCAP evidence.

## Lab PCAP worker

The PCAP worker is a separate five-feature contract trained on bounded Normal
lab traffic. Its IF/AE artifacts, calibration manifest and six holdout
manifests are private and hash-bound. The six existing holdouts yielded the
documented Python hybrid result TP=3, FP=0, FN=0, TN=3; standalone IF/AE was
TP=3, FP=3, FN=0, TN=0. The Suricata SID 9103003 replay is only an RST
telemetry proxy and is not equivalent to the Python hybrid, which counts
features and combines protocol evidence outside one signature.

## Threats to validity

The datasets use different flow definitions, label semantics and observation
windows. Feature overlap, host/time dependence, background-label ambiguity,
non-finite values and small controlled lab corpora limit generalization. No
claim of zero-day detection, production FPR, or automatic rule deployment is
made. All generated rules remain `approved=false`, `deployable=false` and
`deployed=false`.
