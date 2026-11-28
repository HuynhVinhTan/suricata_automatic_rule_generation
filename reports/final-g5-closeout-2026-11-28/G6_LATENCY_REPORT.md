# G6 latency report

## Measurement boundary

Available measurements come from older, identified research/pipeline evidence. Their source, sample count, and limits are kept beside each value. They do not form a single end-to-end T0-T11 trace. No G5 runtime measurement was created in this session.

Durations use monotonic clocks only when the source trace recorded them within one process. The historic EVE-to-ledger interval uses timestamps from the same VM3 host; no cross-host clock subtraction is made. Approval wait is human time and remains separate from automated pipeline latency. Nested sub-stages are not summed into their parent.

## Measured evidence

| Stage | Source and session | Boundary | Unit | Samples | Result |
|---|---|---|---|---:|---:|
| Feature extraction | `docs/new-ml-rule-lineage-and-latency-2026-11-12.md`, lineage run `lineage-new-generated-20261112-04` | Local pipeline stage | ms, monotonic trace | 1 | 113.483 |
| Frozen IF/AE inference | Same lineage trace | Local model inference call | ms, monotonic trace | 1 | 1,602.986 |
| RST evidence / legacy Hybrid decision | Same lineage trace | Narrow decision call only | ms, monotonic trace | 1 | 0.023 |
| Rule generation and artifact write | Same lineage trace | Local pipeline stage | ms, monotonic trace | 1 | 7.559 |
| Local artifact/hash validation | Same lineage trace | Local validation stage | ms, monotonic trace | 1 | 0.187 |
| EVE timestamp to ledger commit | `docs/final-showcase-packet-evidence-2026-11-13.md`, 607 VM3 records | VM3 event timestamp to VM3 ledger commit timestamp | s, same-host timestamps | 607 | min 31.033256; median 235.973714; P95 303.697609; max 358.519941 |

The 0.023 ms value is not full Hybrid evaluation. The current pipeline records port-diversity, handshake, Hybrid evidence, decision, rule generation, and validation separately, but the accessible report does not publish all separate numeric values. Suricata syntax validation passed in historical experiments, but its duration is not available here.

## Coverage and unmeasured stages

`G6_LATENCY_TABLE.csv` contains the requested stage-by-stage register. Capture start/sealing, handoff, receipt, queue wait, current G5 startup, active probes, rollback, cleanup, production-state comparison, and owner approval wait have no current verifiable durations. Historical G5R4 runtime-stage timing files are referenced by hash in the frozen manifest but their raw contents were unavailable for this session, so no durations were re-entered from memory.

## Interpretation

The recorded pipeline stages are isolated samples and should not be added to the 607-record EVE-to-ledger distribution. The EVE-to-ledger interval is not activation latency. The current G5 observer changes have no runtime timing data. All absent values remain `NOT_MEASURED`, never zero.
