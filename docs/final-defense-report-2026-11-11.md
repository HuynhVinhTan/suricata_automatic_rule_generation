# Suricata AI IDS Final Acceptance Report

## Decision

Phases 1 and 2 are accepted for the bounded VM1/VM2 laboratory experiment.
Phase 3 is **not met**: no safe executable Suricata rule was generated or
validated. The Python hybrid review separated the six fresh holdouts, but the
frozen standalone IF/AE models did not.

This result is not a production-accuracy claim. Only three independent Attack
sessions and three independent Normal sessions were tested in one controlled
lab environment.

## System and workflow

VM1 (`192.168.10.10`) runs Suricata 8.0.3 and captures `ens33`. VM2
(`192.168.10.20`) generates bounded traffic. VM3 (`192.168.10.30`) hosts the
frozen-model and worker environment. The operational path remains
Suricata -> EVE -> Filebeat -> ELK; the experimental path is PCAP -> five
SYN-window features -> frozen Isolation Forest and NumPy Autoencoder ->
review-only Python hybrid layer.

The frozen model SHA-256 is
`206dadafc8d6cd96e21d838a52211d9b06d4a6ec541ea5c9a9ae8a6724ffbf5d`. Its five
features are SYN count, unique destination ports, repeated probes, median
inter-SYN interval and SYN rate. No model, feature contract or official
benchmark was changed.

## Calibration and provenance

Three Normal sessions were accepted with capture-time manifests, full snaplen
262144, complete packet records and zero original kernel drops. The calibration
decision was frozen before holdouts at:

- minimum 60-second distinct destination ports: 4
- minimum correlated RST/RST-ACK responses: 3
- maximum Normal handshake failures: 2

Calibration configuration SHA-256:
`814e17006c5cfee433477128e9d29abf7e403e28948d78a968c46c800b67e060`.
Decision SHA-256:
`c7dffd3021d0c0195789e45c369f30108186753076b95586a2d80c9c744b579a`.

All nine accepted evidence manifests were independently re-read. PCAP hashes
and manifest hashes are recorded in the private evidence directories; raw PCAPs
remain excluded from Git.

## Performance

| Detector | TP | FP | FN | TN | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Frozen IF/AE consensus | 3 | 3 | 0 | 0 | 0.500 | 1.000 | 0.667 | 1.000 |
| Python hybrid review | 3 | 0 | 0 | 3 | 1.000 | 1.000 | 1.000 | 0.000 |

The IF and AE models each flagged all five windows in every fresh Attack and
Normal session. The hybrid classified all three Attack sessions as
`reconnaissance_consistent` and all three Normal sessions as
`anomalous_not_reconnaissance`.

The observed hybrid result is a controlled laboratory result, not a production
accuracy estimate or a claim of generalization.

## Suricata baseline and rule feasibility

The existing isolated Suricata evidence for the rejected candidate recorded
baseline and augmented whole-PCAP results of TP=1, FP=1, FN=0, TN=0, precision
0.5, recall 1.0, F1 0.667 and FPR 1.0. That candidate was rejected because it
alerted on Normal traffic as well as Attack traffic.

No new executable rule was generated or replayed for the fresh experiment.
Suricata syntax cannot express the complete Python verdict: unique destination
port counting over a sliding window, correlated RST evidence, handshake
failure conditions and frozen ML consensus. An RST-only rule would be a narrow
proxy and would create false positives on legitimate failed connections.

The smallest viable alternative is a review-only architecture: keep the Python
hybrid as the decision layer and, only after owner approval, use Suricata for a
narrow telemetry/proxy signal whose semantics are explicitly not equivalent to
the hybrid verdict. A future exact implementation would require stateful
correlation outside one Suricata signature and a new approval-controlled
integration.

## Safety and reproducibility

All review artifacts link the source PCAP, feature CSV and frozen-model hashes.
Calibration provenance is accepted, and every fresh review has exact boolean
`approved=false`, `deployable=false` and `deployed=false`. Production Suricata,
Filebeat, EVE-to-ELK, firewall settings and privileges were not modified by
the experiment.

The temporary HTTP service and tcpdump processes are gone, and port 18081 is
closed. The final audit still reports `/usr/bin/tcpdump cap_net_raw=ep`; owner
cleanup therefore remains unresolved and must be completed interactively.
The current production Suricata YAML SHA-256 is
`6224bc7d0bc04d97c4282f54a71e0736341341aa82c530fe22aed3da28814d72`; the
deterministic rules-directory manifest SHA-256 is
`e777054b67fde71cd97cf7e443a4359f71372a8749d4b91cd2dcba6fdc17ba64`.

## Final acceptance ledger

| Criterion | Result |
|---|---|
| Normal calibration evidence | Met for three bounded lab sessions |
| Frozen thresholds before holdouts | Met |
| Independent Attack/Normal holdouts | Met for 3 + 3 controlled sessions |
| Standalone IF/AE separation | Not met |
| Python hybrid separation | Met in this bounded lab |
| Safe executable Suricata rule | **Not met** |
| Baseline versus augmented Suricata improvement | Not demonstrated |
| Production safety | Preserved |
| tcpdump capability cleanup | **Owner action still required** |
