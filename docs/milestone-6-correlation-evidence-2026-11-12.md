# Milestone 6 Correlation Evidence

## Acceptance decision

Milestone 6 is partially accepted. All six original holdout PCAPs have a
verified event/flow-level join to their isolated Suricata 8.0.3 replay output
and validated AI Worker review artifact. The six worker summaries were not
found in the existing `suricata-ai-summary` index, so this is not claimed as a
complete production-index correlation.

## Correlation method

The join key is the worker run ID plus exact PCAP SHA-256. Each EVE output was
copied unchanged from the prior isolated replay directory on VM1. TCP flow
tuples were reconstructed from the original PCAP and compared with EVE source
and destination tuple fields; EVE timestamps were required to fall within the
PCAP timestamp window.

The derived envelope is versioned as `suricata_ai_correlation_v1` and is stored
in the lab-only index `suricata-ai-correlated-lab`. Its stable document ID is
`sha256(run_id + ":" + pcap_sha256)`. Duplicate writes were replayed and each
existing document matched byte-for-byte after the expected HTTP 409 conflict.

## Six-run evidence

| Original worker run ID | Scenario | PCAP SHA-256 | Manifest SHA-256 | EVE SHA-256 | AI summary SHA-256 | AI summary document ID | Hybrid classification | EVE events | Flows | SID | Review status |
|---|---|---|---|---|---|---|---|---:|---:|---:|---|
| `worker-attack-holdout-01-20261111` | attack | `7eb27fe774c8d889480662eaaea1e68b2336cc04c943ff06be399a24e4c0bbb5` | `57d7adc0a48baf2c48a76bda5bad71a319c1f16790edf324f9e0dfd8afef34c5` | `a7ea7181c642a86262032149f88faa50e1ebf668eb2aa9bb9cb22d8a1156de80` | `982a508b21421ecf8321c68734321645b50f5f7ff10f2f3267ae8eaccd69f29b` | `81ba974e8f5e27b642c68339c4f8568d46ad06718dc7edea978915b337fb7ba9` | `reconnaissance_consistent` | 32 | 24 | 9103003 | needs_review |
| `worker-attack-holdout-02-20261111` | attack | `80b118068f89f0939d9a3c9ba72c977b08f95eff74a04e65b31cd548e0258f61` | `09cae81283f4cd0c97eef0b1b567471b16d3a8b45d219fe8c558843680407ff5` | `d75fb77b6791525aba1424002b47c6126c91ba0411fba4eb9cc09f7020369a99` | `b95d1796e23c1e29f5adbdd1d3410a6657bb070ab38ab0c1a6cf24fa837bc3e1` | `534619c61538ece4596656b0021cc0d2a5d6e9d74eb215d0f7e8b6aa4486593f` | `reconnaissance_consistent` | 32 | 24 | 9103003 | needs_review |
| `worker-attack-holdout-03-20261111` | attack | `837dd0b52f3472ce620baf9479f7f44da7515901455f54e2fe907277648a3343` | `15dcd2cbed2a23f146a4b477140a51a27ef0759f3718a86cbc43654252d77e71` | `b72354aacba9eb52f2073bcae827089ff96697730abc0a4048f254c27e52e484` | `b119130e14cc458f6b83dee689c71dc4a658a7fbe944adcf1f800928a7b8ed40` | `12add31a52e73c3b66caa1496bcfe3d55dc3c510a3fd04d5e09e94b38bce348f` | `reconnaissance_consistent` | 32 | 24 | 9103003 | needs_review |
| `worker-normal-holdout-01-20261111` | normal | `a4500b006908c26ffeed932244148c7372f2be2cb8abeb954cfe17ad3cda0fe7` | `d5d3a0fc1cf9f5b91fb87e20888394566844b373c66598b831698aca3e30391e` | `41d7d9d0c7fe154fe83ef90024673d83c1a392eb9e7ddd03290d8cc682d7d7f3` | `3814c8492963d1af2a8f093e45f393b5620cf2ece0bfcc83462e26ee650fcc01` | `94196839927fd549b868591af08fd1c6ff6324bf9569efb4c9f795fe069e8559` | `anomalous_not_reconnaissance` | 72 | 24 | 9103003 | no_candidate |
| `worker-normal-holdout-02-20261111` | normal | `aad42d5710eb1006b76b744983744f47322137b2703126537b46787e34b01aaf` | `1b24e57ec3be8466f33aa971992c27bba5ec6c3edf7b8ff88aa32f4f7a537ab4` | `429cef86e277b179b7c734be6a07216958397f23488abbab4fcbc7f9975a63bf` | `a08e7b5c58773a2f8e0b2b4157bac5ee3c81c34fee349c6eb91cd4242118cc55` | `42fea2b94a1ce03285a92ea139a90b9f4bd27e0b7781fee5b8dcf861793ebf75` | `anomalous_not_reconnaissance` | 69 | 24 | 9103003 | no_candidate |
| `worker-normal-holdout-03-20261111` | normal | `5a61ae059d8f25a2aa6bf1672f82d66c36f3e64de8d9d01dde6afca5081a2468` | `0e77a19e25d69d8ae7ad4b5db994a874b597adbd41901a00f4e7922b45bb8123` | `906285292349849ee1fbe431060bcb3b815ea1a0d7b8b1ad6ad98cf125aa8978` | `6043d9dbe33f9223533804d6c77486eed2781ee82f1424c4b7a723271a1b134a` | `478005c2575c6c7f44da9d6d2ddc271899c17b3ac03bb5816bf4b9428dda14b0` | `anomalous_not_reconnaissance` | 66 | 24 | 9103003 | no_candidate |

Totals are 303 matching EVE events and 144 matching flows. Every envelope has
`correlation_level=event_verified`, the frozen model SHA-256, calibration
SHA-256 `814e17006c5cfee433477128e9d29abf7e403e28948d78a968c46c800b67e060`,
SID `9103003`, and all three safety booleans false.

## Elasticsearch and Kibana

`suricata-ai-correlated-lab` contains exactly six documents. The dedicated
Kibana data view is `Suricata AI Correlated Lab`. The existing dashboard now has
panels for scenario, hybrid classification, SID matches, SHA provenance,
verification status and safety flags.

The deterministic AI summary IDs and hashes identify the six local worker
summary artifacts. `ai_summary_indexed=false` is intentionally retained because
the existing `suricata-ai-summary` index contains four unrelated historical
documents and none of these six PCAP hashes. Native EVE and existing indices
were not modified.
