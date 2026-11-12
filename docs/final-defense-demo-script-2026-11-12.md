# Final defense demo script

1. Show the three-VM boundary and state that VM1 production Suricata/Filebeat
   was not reloaded or changed.
2. Open `artifacts/audits/dataset-quality-20261112/quality_summary.json` and
   show the exact CTU results: zero duplicate rows in all four files and
   contradictory selected-vector counts of 354, 14,873, 168 and 859.
3. Show the frozen model SHA and the existing UNSW report. State that the
   official test was not rerun.
4. Show the six correlation envelopes and explain the 303 EVE events and 144
   flows. Keep the RST proxy SID 9103003 separate from Python Hybrid logic.
5. Show `docs/baseline-comparison-evidence-2026-11-12.md`: the new VM1 active
   ruleset hashes, precommitted reconnaissance SID manifest, six pinned PCAPs,
   real EVE evidence and session metrics. State clearly that this is a new
   baseline, not reconstruction of the historical ET snapshot.
6. Show the new lineage run `data/private/lineage-new-generated-20261112-04/`:
   frozen predictions, Hybrid evidence, generated SID 9103012, artifact hashes
   and `latency-trace.json`. Point out that owner approval, load, first alert
   and rollback have no elapsed value and are `not_measured`.
7. Run the focused lifecycle tests. Show that unsigned replay booleans,
   spoofed/expired approval, SID collisions, unsafe roots and audit tampering
   fail closed.
8. Run the generated-artifact registration CLI in a synthetic or existing
   review-only fixture. Show `PROPOSED` and the three exact false safety flags.
9. Show [documented-rule-recovery-2026-11-12.md](./documented-rule-recovery-2026-11-12.md) and explain that accepted rule text was recovered from a pinned Git evidence blob, while historical RST metadata remains unavailable.
10. Show the real VM1 Suricata 8.0.3 syntax run `syntax-20261113-02` and the
    offline replay run `replay-20261113-04`. Attack-02/03 produced candidate
    alerts; Normal-01/02/03 also produced candidate alerts.
11. Show the sanitized SID 9103012 evidence index. State the exact result:
    TP=2, FP=3, FN=0, TN=0, Precision=0.4000, Recall=1.0000, F1=0.5714 and
    FPR=1.0000. Attack-01 is the discovery input and remains excluded. State
    clearly that the candidate was rejected and no signed attestation exists.
12. Show dry-run staging below the isolated root. Do not activate without an
   authenticated owner authorization, `tcpreplay`/loopback prerequisites and an available isolated runtime.
13. Close with the scoped decision: the recovered 9103003 six offline replays
    and replay signing remain separate historical evidence; new SID 9103012
    validation was rejected for false positives; owner approval and live
    activation/rollback remain blocked and were not attempted.

## Questions to answer

- Does this prove production accuracy? No. It proves only the six bounded lab
  correlations and preserves their provenance.
- Is SID 9103003 the complete hybrid detector? No. It is an RST telemetry
  proxy; Python remains authoritative for the full hybrid evidence.
- Can a worker summary approve a rule? No. Registration is review-only, and
  validation plus authenticated owner authorization are separate gates.
- Why is CIC not used for a new model? The audited files contain non-finite
  rate values and duplicate headers, and no verified adapter/training lineage
  exists.
