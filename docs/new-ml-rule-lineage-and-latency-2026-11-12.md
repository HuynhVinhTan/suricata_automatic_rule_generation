# New ML-to-rule lineage and latency evidence

Run: `lineage-new-generated-20261112-04`.

This is a separate, new review-only execution. It does not recover or rewrite
SID 9103003 history. It used the frozen model and calibration artifacts without
retuning them.

| Artifact | SHA-256 / result |
|---|---|
| Source PCAP | `7eb27fe774c8d889480662eaaea1e68b2336cc04c943ff06be399a24e4c0bbb5` |
| SYN feature CSV | `a23c11dd782080e30e85ad848b4e2351cbc016b8ef0aa290d5fb5908998cdb10` |
| Frozen model | `206dadafc8d6cd96e21d838a52211d9b06d4a6ec541ea5c9a9ae8a6724ffbf5d` |
| Calibration | `814e17006c5cfee433477128e9d29abf7e403e28948d78a968c46c800b67e060` |
| Generated SID | `9103012` (new lineage run; SID 9103011 remains the separately validated candidate) |
| Canonical generated rule | `bd7ac80605988c5a35fa5180380b3f35c2b2870613cf20fa274a0fdd0fbd24d3` |
| Generated rule file | `d86c9222744bcf4aa88d2995354116a1149b772e3a5fe653d2d0ce3112af0e14` |
| Contemporaneous metadata | `3e8633330ff7080f0dc491b56c2cb9a144598082235c9e323d4b2ee2bc6a4704` |
| Latency trace | `4e695e95e3f11ec29e5c846ba57579c25d895903703ded2b4db88aeed096dc94` |
| Private evidence directory | `data/private/lineage-new-generated-20261112-04/` |

## Additive Suricata validation of SID 9103011

Run `sid-9103011-validation-20261112-e7a1895` used Suricata 8.0.3, the same six pinned PCAPs, a fresh exclusive VM1 result root, and the exact config and new-copy baseline hashes. Attack-01 is the discovery/source PCAP; the other two Attack sessions and all three Normal sessions are additional replay cases. The private report is `data/private/sid-9103011-validation-20261112-e7a1895/report.json`, SHA-256 `6d4623546262ebc08394f8825c42c4d0b3acd6e5d4c43c50317f382c1e702fc5`.

Syntax `-T` passed for baseline and augmented arms (53,249 and 53,250 active SIDs). Candidate-only session result: TP=3, FP=3, FN=0, TN=0; Precision=0.500, Recall=1.000, F1=0.667, FPR=1.000. The candidate is **REJECTED** for false positives; no approval or deployment occurred. Candidate rule canonical SHA is `8b2391f922cd45566d776f60ceabfceee061c548567d5e76515a2284cf94a0af`; config and baseline SHA are `6224bc7d0bc04d97c4282f54a71e0736341341aa82c530fe22aed3da28814d72` and `30d7a02cd85f7f7544231a91008a20dedbb15ff0e11ca388ac07aa8d564bf36b`.

Candidate EVE SHA-256 values: attack-01 `b7e7d4f969b88c930c290a135d11dc50f0548f10308caf101e9e265edb7b1641`; attack-02 `0056c4e0c256d1d5a5c14214c94f078e0a3d8c32ea9d319c7490730d40165c56`; attack-03 `eca029080e949821551f9a9a95c0fb83f7cddf5128026ed40f310bcf67dc8853`; normal-01 `834f1b6beccb53b9c0a835478e43d52d6b4cbf976ed7cef5484ae37e8fab7d42`; normal-02 `231dd162c1e75519159bc09070026138787d012a7483e424fea8f406085f76ca`; normal-03 `4e8b34d69e58010bab913c06458c75efd4645aece0796565b77ba80c592d81e2`.

## Measured stages

| Stage | Monotonic elapsed milliseconds | UTC boundary recorded |
|---|---:|---|
| Feature extraction | 113.483 | Yes |
| Frozen IF/AE inference | 1,602.986 | Yes |
| RST evidence extraction / pure Hybrid decision | 0.023 (legacy trace’s narrow decision measurement) | Yes |
| Port-diversity, TCP handshake and full Hybrid evidence extraction | recorded as separate stages in the current pipeline trace | Yes |
| Rule generation and artifact write | 7.559 | Yes |
| Local artifact/hash validation | 0.187 | Yes |
| Suricata syntax validation | NOT MEASURED in this lineage trace; measured separately by the additive replay report above | Separate evidence |
| Owner approval | NOT MEASURED | No approval supplied |
| Rule load | NOT MEASURED | Live activation blocked |
| First verified alert | NOT MEASURED | Live activation blocked |
| Rollback | NOT MEASURED | Live activation blocked |

The legacy immutable trace’s 0.023 ms value is not a full Hybrid latency: it is the narrow decision call. The current pipeline separately records evidence extraction and `hybrid_decision_only`; it does not rewrite the historical trace.

The generated candidate status is `needs_review`; `approved`, `deployable` and
`deployed` remain false. The first same-input attempt is separately preserved
as `data/private/latency-lineage-new-20261112-01/` and failed closed because
capture-integrity metadata was not supplied; the CLI rerun 03 is also preserved
as a failed closed execution. Neither failed run is used as successful evidence.
