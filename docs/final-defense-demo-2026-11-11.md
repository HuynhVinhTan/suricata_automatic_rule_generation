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
7. Show the prior isolated Suricata rejection evidence and explain why the
   executable signature cannot count unique ports or correlate the full hybrid
   verdict.
8. Show production service status and configuration hashes. Do not reload or
   deploy rules during the demonstration.

## Evidence screenshots still needed

- VM1 `getcap -v /usr/bin/tcpdump` after owner cleanup. The current audit still
  shows `cap_net_raw=ep`; this screenshot is a required owner-controlled
  cleanup gate and must be marked FAILED until it shows no capability.
- VM1 `systemctl is-active suricata` and `systemctl is-active filebeat`.
- VM1 production `suricata.yaml` and ruleset hash output.
- The frozen calibration decision with timestamp and threshold fields.
- One complete Attack and one complete challenging Normal PCAP manifest with
  zero-drop evidence and SHA-256.
- Worker review artifacts showing source PCAP, feature CSV and model hashes.
- A side-by-side metric table showing IF/AE versus Python hybrid results.
- The rejected isolated Suricata baseline/augmented replay evidence.
- A final negative screenshot showing no production rule reload or deployment.
