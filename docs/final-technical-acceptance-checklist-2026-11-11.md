# Final technical acceptance checklist

Date: 2026-11-11
Branch: `feat/pcap-ai-worker-integration`

| Gate | Decision | Evidence / limitation |
|---|---|---|
| Three-VM architecture and production monitoring preserved | PASS | VM1 Suricata/Filebeat remained active; no production reload or EVE-to-ELK change |
| Frozen IF/AE identity and five-feature contract | PASS | Model SHA-256 `206dadafc8d6cd96e21d838a52211d9b06d4a6ec541ea5c9a9ae8a6724ffbf5d`; no retraining |
| Normal calibration provenance | PASS in bounded lab | Three accepted manifests with PCAP SHA-256, complete records, full snaplen and original zero-drop evidence |
| Threshold chronology | PASS | Ports `4`, RST/window `3`, handshake failures `2`; freeze preceded all six holdouts |
| Independent holdout provenance | PASS in bounded lab | Three Attack and three Normal sessions, unique run IDs and generator invocations |
| Standalone IF/AE evaluation | PASS as reported | TP=3, FP=3, FN=0, TN=0, FPR=1.0 |
| Python hybrid evaluation | PASS as reported | TP=3, FP=0, FN=0, TN=3, observed FPR=0.0 |
| Review-only safety | PASS | `approved=false`, `deployable=false`, `deployed=false` exact booleans |
| Safe executable Suricata rule | NOT MET | No rule can express the validated unique-port/window/RST/handshake conjunction safely |
| Baseline versus augmented improvement | NOT DEMONSTRATED | No safe candidate existed to replay |
| tcpdump capability cleanup | FAILED / OWNER ACTION REQUIRED | VM1 still reports `cap_net_raw=ep`; no removal was attempted by this audit |

The six holdouts are controlled-lab evidence, not a production accuracy claim.
The rule-generation criterion must not be declared complete.
