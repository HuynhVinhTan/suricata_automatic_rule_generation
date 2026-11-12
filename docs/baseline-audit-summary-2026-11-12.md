# Baseline evidence audit

The private baseline report was independently audited by
`scripts/audit_baseline_report.py`. The audit rehashed every private EVE file
against the report and checked the six-session shape and `NEW_VM1_COPY_2026-11-12`
provenance. Raw PCAPs, raw EVE content and credentials are not included in this
document.

| Session | Label | Baseline EVE events / recon | Augmented EVE events / recon |
|---|---|---:|---:|
| attack-01 | Attack | 25 / 0 | 33 / 8 |
| attack-02 | Attack | 25 / 0 | 33 / 8 |
| attack-03 | Attack | 25 / 0 | 33 / 8 |
| normal-01 | Normal | 146 / 0 | 146 / 0 |
| normal-02 | Normal | 150 / 0 | 150 / 0 |
| normal-03 | Normal | 142 / 0 | 142 / 0 |

Private audit output: `data/private/baseline-audit-20261112/audit-summary.json`,
SHA-256 `227dfd028b206d362773471b4f3687bc64f1adc9b0c4334ecb0935b1e9d85033`.
The reconnaissance allow-list
SHA-256 is `80e343a0c25642834424c13f0ee4fc80845a00a3fba6679d1bc68d402e119360`.

Reproduction requires access to the private VM1 result tree and report:

```text
python scripts/audit_baseline_report.py \
  --report data/private/baseline-audit-20261112/report.json \
  --eve-root data/private/baseline-audit-20261112/baseline-new-vm1-20261112-aef06c2 \
  --recon-sids data/private/baseline-new-vm1-20261112-aef06c2/recon-sids-20261112.txt \
  --out data/private/baseline-audit-20261112/audit-summary.json
```

The allow-list was defined from active copied rules whose `classtype` was
`attempted-recon` or `network-scan`, with SID 9103003 explicitly included,
before the replay as reported in the experiment record. It is not an externally
authenticated precommit timestamp. The copied VM1 ruleset is a NEW baseline;
the unavailable historical Emerging Threats snapshot is not reconstructed.
