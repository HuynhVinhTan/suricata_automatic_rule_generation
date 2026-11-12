# Suricata AI IDS Final Acceptance Report

## Decision

Phases 1 and 2 remain accepted for the bounded VM1/VM2 laboratory experiment.
Milestone 4 is met for the existing EVE-to-ELK path and review-only Kibana
dashboard. Milestone 5 is met only for a validated review-only RST telemetry
proxy; it is not the complete Python hybrid decision. Milestone 6 is fully
accepted for six lab experiments: derived envelopes prove six PCAP-to-EVE-to-
worker-artifact joins at event/flow level, and six derived worker summaries
passed exact read-back in the existing `suricata-ai-summary` index. Live
production EVE correlation by run ID is not claimed.

The dataset audit found the local UNSW, CIC-IDS2017 and CTU-13 files and
recorded their hashes and streaming quality findings. CIC has non-finite rate
values and no verified adapter/model; UNSW has identical selected feature
vectors with contradictory labels; CTU labels retain Background separately
from Normal and Botnet. The review-only rule lifecycle now requires explicit
provenance-bound approval and defaults to dry-run isolated staging.

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

The complete Python verdict remains non-expressible by one Suricata signature:
unique destination
port counting over a sliding window, correlated RST evidence, handshake
failure conditions and frozen ML consensus. An RST-only rule would be a narrow
proxy and would create false positives on legitimate failed connections.

The validated alternative is a review-only architecture: keep the Python hybrid
as the decision layer and use Suricata SID 9103003 only as a narrow telemetry
proxy. The candidate uses `flags:R+`, `track by_dst`, threshold 3 in 60 seconds,
and rule SHA-256
`7182bb328ce4ed1230c6de9b20c825d458b8c224a494d6b2a60063cca5ec21df`. It
triggered 3/3 Attack sessions and 0/3 Normal sessions in isolated Suricata
8.0.3 replay. The status is `validated_for_review`; approved, deployable and
deployed are all false. This does not count unique ports or implement the full
hybrid verdict.

The original generated RST metadata was not recovered from the local, VM1 or
VM3 artifact searches. The accepted rule was instead recovered from the
unchanged pinned Git evidence blob and is explicitly labelled
`documented_frozen_rule_recovery`; this does not claim historical generator
provenance. A fresh VM1 Suricata 8.0.3 offline replay of the six immutable
holdouts produced 8/8/8 candidate SID alerts for Attack 01/02/03 and 0/0/0 for
Normal 01/02/03, with nonempty EVE output. The replay was independently signed
with the VM1 replay Ed25519 key and verified on Windows. The signed attestation
SHA-256 is `aaab81a187dc0640cc73bb05fe4ce2feda93b1be9af21922bcf532d15573c5ce`;
its replay run is `documented-frozen-rule-signing-20261112-01` and its signed
evidence directory is `replay-evidence/signed-documented-frozen-rule-signing-20261112-01`.
Owner approval and live loopback activation remain blocked: `tcpreplay` is
unavailable on VM1 and no owner authorization was requested or generated.

## Safety and reproducibility

All review artifacts link the source PCAP, feature CSV and frozen-model hashes.
Calibration provenance is accepted, and every fresh review has exact boolean
`approved=false`, `deployable=false` and `deployed=false`. Production Suricata,
Filebeat, EVE-to-ELK, firewall settings and privileges were not modified by
the experiment.

The temporary HTTP service and tcpdump processes are gone, and port 18081 is
closed. The final audit at `2026-11-11T17:34:31Z` reports
`getcap -v /usr/bin/tcpdump` as `/usr/bin/tcpdump`, with no capability text.
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
| Review-only RST proxy rule | **Met: validated_for_review, SID 9103003** |
| Complete hybrid logic in Suricata | **Not met by design** |
| Baseline versus augmented Suricata comparison | Met for proxy gate: 3/3 Attack, 0/3 Normal |
| Production safety | Preserved |
| tcpdump capability cleanup | **Met: no capability reported** |
| Real replay Ed25519 attestation | **Met with real evidence** | Attestation SHA-256 recorded above; independent pinned-key verification passed |
| Owner approval and isolated activation/rollback | **Blocked by explicit gate** | No owner approval generated; `tcpreplay` missing and live loopback injection prerequisites remain unproven |

PR #2 review-fix evidence is documented in
`docs/pr2-review-fixes-evidence-2026-11-12.md`. The dataset audit is strict and
disk-bounded; lifecycle approval and activation remain fail-closed and
review-only.
