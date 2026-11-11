# Suricata AI IDS Defense Demonstration

## Demonstration order

1. Show the three-VM topology and identify production Suricata/Filebeat as
   separate from the private experiment directories.
2. Show the frozen model SHA-256 and the five-feature contract.
3. Show the three calibration manifests, the frozen decision timestamp and
   thresholds. Explain that holdout generator timestamps begin after the freeze.
4. Show one Attack and one Normal holdout manifest, then show the worker
   `review.json` artifacts for all six fresh runs.
5. Show that IF/AE flags both classes, while the Python hybrid conditions
   separate the classes.
6. Show the exact safety booleans: `approved=false`, `deployable=false`,
   `deployed=false`.
7. Show the isolated Suricata 8.0.3 replay for SID 9103003: 3/3 Attack
   sessions and 0/3 Normal sessions. Explain that it is a telemetry proxy and
   cannot count unique ports or implement the full hybrid verdict.
8. Show the six correlation envelopes, exact PCAP/EVE/summary hashes, 303
   matching EVE events and 144 matching flows in
   `suricata-ai-correlated-lab`. Show the six exact read-backs in
   `suricata-ai-summary` alongside the four preserved historical documents.
   State that this is experiment-level correlation only; live production EVE
   correlation by run ID is not claimed.
9. Show production service status and configuration hashes. Do not reload or
   deploy rules during the demonstration.

## Evidence screenshots still needed

- VM1 `getcap -v /usr/bin/tcpdump`, showing `/usr/bin/tcpdump` with no
  capability text.
- VM3 Elasticsearch health, `suricata-eve-*` indices, `suricata-ai-summary`,
  the two data views, and `Suricata AI IDS Lab Dashboard`.
- VM1 `systemctl is-active suricata` and `systemctl is-active filebeat`.
- VM1 production `suricata.yaml` and ruleset hash output.
- The frozen calibration decision with timestamp and threshold fields.
- One complete Attack and one complete challenging Normal PCAP manifest with
  zero-drop evidence and SHA-256.
- Worker review artifacts showing source PCAP, feature CSV and model hashes.
- A side-by-side metric table showing IF/AE versus Python hybrid results.
- The isolated Suricata SID 9103003 baseline/augmented replay evidence.
- The dedicated `suricata-ai-correlated-lab` index, its data view and six
  stable documents.
- A final negative screenshot showing no production rule reload or deployment.
