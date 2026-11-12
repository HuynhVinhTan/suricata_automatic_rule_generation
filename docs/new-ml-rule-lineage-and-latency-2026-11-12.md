# New ML-to-rule lineage and latency evidence

Run: `lineage-new-generated-20261112-02`.

This is a separate, new review-only execution. It does not recover or rewrite
SID 9103003 history. It used the frozen model and calibration artifacts without
retuning them.

| Artifact | SHA-256 / result |
|---|---|
| Source PCAP | `7eb27fe774c8d889480662eaaea1e68b2336cc04c943ff06be399a24e4c0bbb5` |
| SYN feature CSV | `a23c11dd782080e30e85ad848b4e2351cbc016b8ef0aa290d5fb5908998cdb10` |
| Frozen model | `206dadafc8d6cd96e21d838a52211d9b06d4a6ec541ea5c9a9ae8a6724ffbf5d` |
| Calibration | `814e17006c5cfee433477128e9d29abf7e403e28948d78a968c46c800b67e060` |
| Generated SID | `9103011` |
| Canonical generated rule | `8b2391f922cd45566d776f60ceabfceee061c548567d5e76515a2284cf94a0af` |
| Generated rule file | `9c60db6cddabbe6e8d8b1df8ac4f109b902be3f2761de3168e23c2b5c530c805` |
| Contemporaneous metadata | `a81974e69b2ceb46e1b3bfcd80e6538d137fdce5476cb140a227568dd2a74d00` |
| Latency trace | `7c30561d145f139c9cfd0e1ccf96772db24c96158c5e3ff294c68d08f2b65f2a` |
| Private evidence directory | `data/private/lineage-new-generated-20261112-02/` |

## Measured stages

| Stage | Monotonic elapsed milliseconds | UTC boundary recorded |
|---|---:|---|
| Feature extraction | 113.483 | Yes |
| Frozen IF/AE inference | 1,602.986 | Yes |
| Hybrid review | 0.023 | Yes |
| Rule generation and artifact write | 7.559 | Yes |
| Rule artifact validation | 0.187 | Yes |
| Owner approval | NOT MEASURED | No approval supplied |
| Rule load | NOT MEASURED | Live activation blocked |
| First verified alert | NOT MEASURED | Live activation blocked |
| Rollback | NOT MEASURED | Live activation blocked |

The generated candidate status is `needs_review`; `approved`, `deployable` and
`deployed` remain false. The first same-input attempt is separately preserved
as `data/private/latency-lineage-new-20261112-01/` and failed closed because
capture-integrity metadata was not supplied.
