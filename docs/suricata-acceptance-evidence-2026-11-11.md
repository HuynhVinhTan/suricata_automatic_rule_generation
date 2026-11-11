# Suricata AI IDS acceptance evidence

## Scope

This record covers the frozen-model replay and the isolated Suricata 8.0.3 lab validation for run `vm3-rulegen-v02`. No model, inference threshold, production Suricata configuration, production rule file, or production service was changed.

## Frozen run provenance

| Item | Value |
|---|---|
| Worker run | `vm3-rulegen-v02` |
| Attack PCAP SHA256 | `681b5e263ac11dc8a4cd1cca80a3b0ced480ce97e0105eaae4595f2c8e97675c` |
| Normal PCAP SHA256 | `bb762a4243455a6388012d9fd733e6d7cd265507a276ad4f97f75e40422286a8` |
| Model SHA256 | `206dadafc8d6cd96e21d838a52211d9b06d4a6ec541ea5c9a9ae8a6724ffbf5d` |
| Generated SID | `9103001` |
| Candidate status | `rejected_validation_failure` |
| Rejection reason | `normal_replay_false_positive` |

The generated rule was `ML REVIEW - SYN packet burst`, using `flags:S` and `detection_filter:track by_src,count 3,seconds 10`. The filter counts matching SYN packets per source; it does not count unique destination ports.

## PCAP comparison

| Evidence | Recon V03 / Attack | Normal Matched12 V02 / Normal |
|---|---:|---:|
| Packets | 964 | 960 |
| Initial SYN packets | 96 | 96 |
| Unique destination ports | 12 | 12 |
| 10-second SYN windows | 17, 17, 16, 17, 16, 13 | 17, 15, 16, 17, 16, 15 |
| Mean inter-SYN interval | 604.049 ms | 621.302 ms |
| Minimum / maximum inter-SYN interval | 601.191 / 613.647 ms | 600.736 / 1156.533 ms |
| Valid SYN-ACK flows | 96 | 96 |
| Completed handshakes | 96 | 96 |
| Bidirectional payload flows | 96 | 96 |
| Flows with RST | 0 | 0 |
| HTTP GET / 200 responses | 96 | 96 |

The Attack HTTP paths were `/version` (24), `/status` (24), `/metrics` (24), and `/admin` (24). The Normal HTTP path was `/health` (96). The path difference is application content, not evidence that `/admin` is malicious. The transport evidence does not distinguish the scenarios reliably; therefore SID 9103001 remains rejected.

## EVE evidence and baseline comparison

| Replay | Total alerts | Alert signatures | Flow events | HTTP events |
|---|---:|---|---:|---:|
| Baseline Attack | 96 | `2034635 ET INFO Python BaseHTTP ServerBanner`: 96 | 96 | 96 |
| Baseline Normal | 96 | `2034635 ET INFO Python BaseHTTP ServerBanner`: 96 | 96 | 96 |
| Augmented Attack | 174 | `2034635 ET INFO Python BaseHTTP ServerBanner`: 96; `9103001 ML REVIEW - SYN packet burst`: 78 | 96 | 96 |
| Augmented Normal | 174 | `2034635 ET INFO Python BaseHTTP ServerBanner`: 96; `9103001 ML REVIEW - SYN packet burst`: 78 | 96 | 96 |

All four replays reported `flow.state=closed` and `flow.reason=shutdown` for 96 flows. All HTTP events were `GET` with status 200. Baseline Suricata did not miss an alert event: it generated the same 96 informational alerts for both replays. It did not provide a scenario-specific attack verdict.

At the whole-PCAP verdict level, both the baseline and augmented SID evidence are positive on both the Attack and Normal replay: TP=1, FP=1, FN=0, TN=0, precision=0.5, recall=1.0, F1=0.667, and false-positive rate=1.0. These two replay samples are not a valid classifier benchmark; the 78/78 SID result is the explicit rejection gate, not a successful detection result. Detection-to-rule-effectiveness latency was not reported as a meaningful production metric because the candidate was rejected and replay was offline; the isolated ruleset reload completed after approximately 22 seconds of engine reload work.

## Isolated Suricata validation

VM1 runs Suricata `8.0.3 RELEASE`. The test instance used a separate YAML file, `augmented.rules`, EVE output, log directory, PID file, and UNIX command socket below `/home/tanhv/suricata-rule-review/isolated-vm3-rulegen-v02/`. `suricata -T --init-errors-fatal` passed. The daemon started with only the loopback `af-packet` interface. `suricatasc` returned version `8.0.3 RELEASE` and an `OK` uptime response. `ruleset-reload-rules` completed, with `detect: rule reload starting` followed by `detect: rule reload complete` in the isolated log. Only isolated PID 6854 was stopped.

Before and after isolated validation, VM1 reported `suricata=active` and `filebeat=active`; `logstash` and `elasticsearch` were already inactive. The production rule checksum remained `30d7a02cd85f7f7544231a91008a20dedbb15ff0e11ca388ac07aa8d564bf36b`.

## Limitations and next experiment

The current paired PCAPs intentionally have the same SYN volume, port set, completed handshakes, payload direction, and response behavior. A SYN-burst rule therefore cannot separate them. Future work should use independently collected labels and a protocol- or application-aware feature set, with an untouched Normal replay held out before approval. Any candidate must pass a Normal replay false-positive gate before transfer or deployment.
