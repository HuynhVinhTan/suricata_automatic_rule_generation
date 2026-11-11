# Milestones 4 5 and 6 Acceptance

## Decision

Milestone 4 is accepted. The existing production Suricata EVE to Filebeat to
Logstash to Elasticsearch path is live, and Kibana contains the required data
views plus a review-only dashboard backed by real indexed documents.

Milestone 5 is accepted only for the review-only Suricata RST telemetry proxy.
It does not implement the complete Python hybrid decision. The Python worker
remains authoritative for unique destination ports, correlated RST/RST-ACK
evidence, handshake evidence and frozen IF/AE consensus.

Milestone 6 is not fully accepted. The VM2 to VM1 EVE path and the independent
VM3 AI-summary indexing path are operational, but the production EVE documents
and AI summary documents do not contain a verified shared run identifier or
hash. Therefore this evidence does not claim event-level correlation between
those two document families.

## Live pipeline evidence

The audit ran at `2026-11-11T17:34:31Z` on VM1 and
`2026-11-11T17:34:32Z` on VM3.

| Component | Evidence |
|---|---|
| VM1 Suricata | `active`; Suricata 8.0.3; real `/var/log/suricata/eve.json` receiving events |
| VM1 Filebeat | `active`; journal metrics show the `suricata-eve` filestream published and acknowledged events |
| VM3 Elasticsearch | HTTP health `yellow`, one data node, 64 active primary shards |
| EVE indices | `suricata-eve-*`; current index `suricata-eve-2026.11.11` had 7,674 documents at audit time |
| AI summary index | `suricata-ai-summary` had 4 documents at audit time |
| Beats listener | VM3 TCP `5044` listening on `192.168.10.30` |
| Kibana | HTTP status `200` on `127.0.0.1:5601` |

Real EVE documents contain timestamp, event type, source and destination IPs,
protocol and alert fields where present. Real AI summary documents contain
`generated_at`, `run_id`, PCAP SHA-256, model SHA-256, review status and safety
booleans.

## Kibana objects

Existing data views were retained:

- `Suricata EVE Logs` for `suricata-eve-*`, time field `@timestamp`.
- `Suricata AI Summary` for `suricata-ai-summary`, time field `generated_at`.

Created saved objects:

- Dashboard: `Suricata AI IDS Lab Dashboard`.
- Panels: EVE events over time, alerts by signature, source IPs, destination
  IPs, protocol distribution, flow/event types, AI anomaly and hybrid review
  status, and approved/deployable/deployed safety state.

The AI panel uses the actual indexed `review_status` field. No hybrid
classification field was fabricated because it is not present in the existing
summary mapping.

## Milestone 5 rule evidence

The fresh candidate is derived from frozen Normal calibration only:

- Normal calibration RST maximum: `2`.
- Frozen threshold: `3` RST/RST-ACK responses in `60` seconds.
- SID: `9103003`.
- Rule SHA-256: `7182bb328ce4ed1230c6de9b20c825d458b8c224a494d6b2a60063cca5ec21df`.
- Model SHA-256: `206dadafc8d6cd96e21d838a52211d9b06d4a6ec541ea5c9a9ae8a6724ffbf5d`.
- Calibration SHA-256: `814e17006c5cfee433477128e9d29abf7e403e28948d78a968c46c800b67e060`.
- Decision manifest SHA-256: `c7dffd3021d0c0195789e45c369f30108186753076b95586a2d80c9c744b579a`.

Rule syntax passed isolated Suricata `8.0.3 RELEASE` `suricata -T`. With
identical `-k none` replay settings, candidate session counts were:

| Holdout class | Baseline candidate | Augmented candidate |
|---|---:|---:|
| Attack | 0/3 | 3/3 |
| Normal | 0/3 | 0/3 |

The augmented replay produced multiple alert packets inside an Attack PCAP;
the acceptance unit is one session, not individual alert packets. The result
is `validated_for_review`, with `approved=false`, `deployable=false`, and
`deployed=false`. No production Suricata process was restarted or reloaded.

The earlier `flags:R` direction/flag attempt is rejected evidence: it missed
the Attack RST-ACK packets and matched benign client-side RST traffic. The
validated rule uses `flags:R+` and server-to-client direction.

## Frozen scientific results

The official bounded-lab results remain unchanged:

| Detector | TP | FP | FN | TN | FPR |
|---|---:|---:|---:|---:|---:|
| Frozen IF/AE | 3 | 3 | 0 | 0 | 1.0 |
| Python Hybrid | 3 | 0 | 0 | 3 | 0.0 |

These are controlled-lab holdout results, not production accuracy claims.

## Safety and evidence limits

VM1 still reported Suricata and Filebeat active. The production Suricata YAML
hash was `6224bc7d0bc04d97c4282f54a71e0736341341aa82c530fe22aed3da28814d72`.
`getcap -v /usr/bin/tcpdump` returned `/usr/bin/tcpdump` with no capability
text. No sudoers, Filebeat input, production EVE file, model bundle or
production rule set was changed.

No GUI screenshots were committed. The terminal/API evidence above is
authentic and is paired with the owner screenshot checklist in the defense
demo document.
