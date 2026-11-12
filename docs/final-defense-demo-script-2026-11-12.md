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
5. Run the focused lifecycle tests. Show that unsigned replay booleans,
   spoofed/expired approval, SID collisions, unsafe roots and audit tampering
   fail closed.
6. Run the generated-artifact registration CLI in a synthetic or existing
   review-only fixture. Show `PROPOSED` and the three exact false safety flags.
7. Show [documented-rule-recovery-2026-11-12.md](./documented-rule-recovery-2026-11-12.md) and explain that accepted rule text was recovered from a pinned Git evidence blob, while historical RST metadata remains unavailable.
8. Show the real VM1 offline replay counts: 8/8/8 SID alerts for Attack 01/02/03 and zero for all three Normal holdouts. Show the independently verified signed attestation hash `aaab81a187dc0640cc73bb05fe4ce2feda93b1be9af21922bcf532d15573c5ce` and candidate ID `d1020f83f684675e0547a76b467162fc1371bbf3c3005ec72e9951f1026c4f0a`.
9. Show dry-run staging below the isolated root. Do not activate without an
   authenticated owner authorization, `tcpreplay`/loopback prerequisites and an available isolated runtime.
10. Close with the scoped decision: the six offline replays and replay signing
   passed with real EVE evidence; owner approval and live activation/rollback
   remain blocked because `tcpreplay` is unavailable and no owner approval was generated.

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
