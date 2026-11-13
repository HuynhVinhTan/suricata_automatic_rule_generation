# Final showcase packet/lifecycle evidence — 2026-11-13

This is a sanitized evidence summary. It does not contain private manifests,
packet payloads, private keys, or production credentials.

## Frozen showcase provenance

| Item | Value |
|---|---|
| Deployed source | `32a6d24d7175553ad21d8461d5b7005bb9210cdd` |
| VM archive SHA256 | `f33e7d6f46a59797fda305168c4e27378dcf0fa05e7bcade26ab149c0e6d8b0b` |
| Corrected demo model SHA256 | `616a856fa2bdb885041a2fb127a179040120fd786cf5d26f66e4847f126fd3ab` |
| Development dataset manifest SHA256 | `2ea06350af77c07f4e246817a8393a93ab8921204273768b08c6ef7949764e35` |
| Calibration dataset manifest SHA256 | `fd57dd4517c976f8f1930ea82ba363376e38354ed5ad2b72d8b6d4141fdbdbcf` |
| Independent holdout manifest SHA256 | `0ce228f7993dd309890348f30c55905dd27e6c1acc9eb459410a460507db90f1` |

Each split has unique session IDs, attempt IDs, and canonical EVE event hashes:
development 144/144/144, calibration 96/96/96, holdout 144/144/144; duplicate
event hashes were zero. The corrected binary cohort excludes Normal RST controls.

## Corrected metrics

The independent holdout contains 72 Attack and 66 eligible Normal flows. The
six Normal RST controls remain recorded separately and are not binary examples.

`TP=72, FN=0, FP=0, TN=66`; precision `1.0`, recall `1.0`, F1 `1.0`, FPR
`0.0`. Attack session detection was `3/3`; Normal session false-alert rate was
`0/3`. This is a bounded laboratory demo result and is not a zero-day or
production-model claim.

The historical six-FP matrix is immutable secondary evidence: all six were
Normal RST controls, originally labelled 0, with scores from `0.9139503` to
`0.9140877`; their corrected binary eligibility is false.

## Packet capture gate

VM2 has `eth1`, but the permitted capture method returned:

```text
CAPTURE_BLOCKED: tcpdump lacks cap_net_raw
exit 77
```

The owner-approved bounded command, to execute interactively only after the
owner authorizes the existing capture method, is:

```bash
ssh suricata-vm2 /home/kali/suricata-ai-showcase/current/scripts/demo/vm2-capture-session.sh /home/kali/suricata-ai-showcase/evidence/<RUN_ID>.pcap
```

The wrapper restricts capture to `eth1` and hosts `192.168.10.20` and
`192.168.10.10`; no capability or sudoers change was made. No new PCAP hash,
packet-completeness claim, or packet-derived Hybrid evidence is asserted.

## Hybrid, candidate, and isolated lifecycle status

Existing signed-envelope, replay, tamper, wrong-key, old-sequence, and
restart-persistence tests remain available and pass as code-level gates. A
`LAB_DEMO_ONLY` producer identity was not provisioned because the required
packet-backed PCAP evidence is unavailable; creating synthetic packet evidence
would invalidate the acceptance claim.

No new rule candidate was generated. Candidate generation requires verified
packet/ML evidence, and the production CTU model and packet capture gates are
not satisfied. SID 9103012 remains rejected and untouched. Isolated Suricata
activation, candidate SID alert validation, and rollback therefore remain
`NOT_MEASURED`, not successful.

## Real EVE-to-ML latency

For 607 ledger records, using the VM3 EVE event timestamp and the VM3 ledger
commit timestamp (same host; no cross-host clock comparison):

| Measure | Seconds |
|---|---:|
| Minimum | 31.033256 |
| Median | 235.973714 |
| P95 | 303.697609 |
| Maximum | 358.519941 |

This is EVE timestamp-to-ledger processing latency. T8–T11 candidate activation
stages remain `NOT_MEASURED`.

## Production invariant

Showcase processes were stopped. Production Suricata/Filebeat remained on their
original PIDs (`2164`/`1222`); production rules, YAML, EVE, and Filebeat inputs
were not modified.
