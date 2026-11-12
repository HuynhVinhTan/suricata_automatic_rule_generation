# Suricata baseline-versus-augmented comparison

## Scope and honest status

This is the reproducibility record for the baseline experiment required by the
thesis. It does not rewrite the historical six-PCAP replay evidence and it does
not claim that the historical Emerging Threats snapshot was recovered. The
historical ruleset identity is therefore **not established**. Any comparison
using a newly copied VM1 ruleset must be labelled a newly conducted baseline
evaluation.

VM1 was read-only inspected on 2026-11-12: Suricata was `8.0.3 RELEASE`,
`suricatasc` was present, and the production Suricata and Filebeat services were
active. `tcpreplay` was absent. VM2 and VM3 were not reachable during this
inspection. No service, rule, YAML, interface or privilege was changed.

## Detection definition

Before evaluating results, this report defines reconnaissance detection as:

> At least one alert in a replay whose SID or exact signature is explicitly
> listed in the experiment's reconnaissance allow-list.

Generic decoder, protocol, banner and informational Emerging Threats alerts are
reported as alerts but are **not** counted as reconnaissance detection unless
their SID/signature is in that allow-list. A zero count for SID 9103003 alone
does not prove that the whole baseline missed reconnaissance.

## Reproducible harness

The offline harness is [compare_suricata_baseline.py](../scripts/compare_suricata_baseline.py).
It runs baseline and augmented `suricata -r` replays into separate output
directories, records PCAP/rules/config hashes and parses EVE alert events. The
same PCAP, config, replay order and detection definition are used for both
arms. Example:

```text
python scripts/compare_suricata_baseline.py \
  --config /path/to/isolated.yaml \
  --baseline-rules /path/to/baseline.rules \
  --augmented-rules /path/to/augmented.rules \
  --case attack-01 /private/attack-01.pcap \
  --case normal-01 /private/normal-01.pcap \
  --recon-sid 9103003 \
  --output-root /tmp/suricata-baseline-20261112 \
  --output /tmp/suricata-baseline-20261112/report.json
```

The ruleset inventory utility is
[inventory_suricata_rules.py](../scripts/inventory_suricata_rules.py). It
records each rules file's source classification, size, line count, SID range
and SHA-256, plus the effective YAML hash, without reloading Suricata.

## Available evidence

The accepted historical evidence is the narrower documented-frozen SID replay:

| Arm | Attack sessions | Normal sessions | What it establishes |
|---|---:|---:|---|
| Historical baseline candidate comparison | 0/3 SID 9103003 | 0/3 SID 9103003 | Candidate-specific absence only |
| Augmented documented-frozen proxy | 3/3 SID 9103003 | 0/3 SID 9103003 | Proxy replay result with real EVE |
| Whole enabled ET reconnaissance verdict | NOT MEASURED | NOT MEASURED | Historical ET identity was not recovered |

The earlier paired replay in
`docs/suricata-acceptance-evidence-2026-11-11.md` is preserved separately. It
showed the baseline's generic Python banner alerts on both Attack and Normal;
the rejected SYN-burst candidate also alerted on both. It is not a valid
reconnaissance classifier result.

## Metrics and limitations

For a completed paired run, the harness reports session-level TP, FP, FN and
TN from the explicit reconnaissance verdict, then Precision, Recall, F1 and
FPR can be derived without treating generic alerts as true positives. The
current repository does not contain the private raw PCAPs or a verified
historical ET rules snapshot, so no new whole-ET metric is fabricated here.
The strongest defensible result remains a candidate-specific proxy result,
bounded to three Attack and three Normal sessions.
