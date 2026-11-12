# Final technical acceptance checklist

Date: 2026-11-12
Branch: `feat/isolated-rule-runtime-signing`

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
| Dataset inventory and quality audit | CONDITIONAL | UNSW, CIC and CTU raw files inventoried and hashed; CIC non-finite rates and UNSW feature-vector label contradictions recorded; CTU duplicate audit completed with zero duplicates and persistent contradictions |
| Rule lifecycle safety | PASS for review-only code | Explicit provenance-bound state machine, approval gate, dry-run staging and rollback audit; active isolated-lab installation remains pending owner approval |
| Original RST metadata provenance | BLOCKED | Read-only searches found no genuine accepted RST metadata; documented-frozen recovery is explicit and does not claim historical metadata recovery |
| Real six-PCAP offline replay | PASSED WITH REAL EVIDENCE | VM1 Suricata 8.0.3: Attack 01/02/03 each 8 SID alerts; Normal 01/02/03 each 0; all EVE files nonempty |
| Replay Ed25519 attestation | PASS WITH REAL EVIDENCE | Attestation SHA-256 `aaab81a187dc0640cc73bb05fe4ce2feda93b1be9af21922bcf532d15573c5ce`; independent Windows verification passed; Attack 8/8/8 and Normal 0/0/0 |
| Recovery candidate registration | PASS WITH VERIFIED IDENTITY | Candidate `d1020f83f684675e0547a76b467162fc1371bbf3c3005ec72e9951f1026c4f0a`; documented-frozen provenance; all safety flags false |
| Isolated activation and rollback | BLOCKED | `tcpreplay` is unavailable, packet-injection privileges were not established, and no owner approval was generated; no daemon activation was attempted |

## Candidate SID 9103012 final disposition

| Gate | Decision | Evidence / limitation |
|---|---|---|
| Candidate source integrity and exact provenance | PASS | Candidate record and source artifact hashes are required and verified; candidate remains `PROPOSED` with all safety flags false |
| Suricata 8.0.3 syntax | PASS | VM1 run `syntax-20261113-02`; one rule loaded and configuration exited successfully |
| Independent Attack/Normal replay | PASS as execution / FAIL as candidate gate | VM1 run `replay-20261113-04`; fresh EVE evidence exists for the exact 2-Attack/3-Normal cohort |
| Candidate safety metrics | FAIL | TP=2, FN=0, FP=3, TN=0, Precision=0.4000, Recall=1.0000, F1=0.5714, FPR=1.0000 |
| Signed replay attestation | BLOCKED | The false-positive gate correctly prevented signing |
| Owner approval, activation and rollback | BLOCKED | No private key, owner signature, production change, live activation or rollback was performed |

The six holdouts are controlled-lab evidence, not a production accuracy claim.
The complete-hybrid-in-Suricata criterion is not met; the review-only RST proxy
criterion is met and remains non-deployable.

## PR #2 review-fix closeout

Dataset and lifecycle review-fix evidence is recorded in
`docs/pr2-review-fixes-evidence-2026-11-12.md`. The implementation is
review-only; active isolated installation still requires explicit owner
authorization.
