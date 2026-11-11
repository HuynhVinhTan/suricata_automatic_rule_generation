# Final technical acceptance checklist

Date: 2026-11-12
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
| Milestone 4 EVE-to-ELK | PASS | Live EVE/Filebeat path; `suricata-eve-*` and `suricata-ai-summary` indexed; Kibana objects present |
| Review-only RST proxy | PASS | SID `9103003`, threshold 3/60s, rule SHA-256 `7182bb328ce4ed1230c6de9b20c825d458b8c224a494d6b2a60063cca5ec21df`; 3/3 Attack and 0/3 Normal sessions |
| Complete hybrid logic in Suricata | NOT MET | Python remains authoritative for unique ports, correlated RST, handshake and frozen ML consensus |
| Baseline versus augmented improvement | PASS for proxy gate | Baseline candidate 0/6 sessions; augmented candidate 3/3 Attack and 0/3 Normal |
| Milestone 6 PCAP/EVE/worker correlation | PASS for six lab experiments | Six event/flow-verified envelopes and six exact Elasticsearch read-backs; 303 matching EVE events and 144 matching flows; four historical AI-summary documents preserved |
| tcpdump capability cleanup | PASS | VM1 `getcap -v /usr/bin/tcpdump` returned `/usr/bin/tcpdump` only |

The six holdouts are controlled-lab evidence, not a production accuracy claim.
The complete-hybrid-in-Suricata criterion is not met; the review-only RST proxy
criterion is met and remains non-deployable.
