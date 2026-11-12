# SID 9103012 validation summary

This sanitized summary records the authorized VM1 offline validation. Raw PCAP
and EVE payloads remain private and are not committed.

| Field | Value |
|---|---|
| Candidate ID | `84ad314c885d821fb69713353134671cb355662a6effec1b890d59f38cada7e4` |
| Run ID / SID | `lineage-new-generated-20261112-04` / `9103012` |
| Syntax run | `syntax-20261113-02` |
| Replay run | `replay-20261113-04` |
| Rule SHA256 | `d86c9222744bcf4aa88d2995354116a1149b772e3a5fe653d2d0ce3112af0e14` |
| Canonical rule SHA256 | `bd7ac80605988c5a35fa5180380b3f35c2b2870613cf20fa274a0fdd0fbd24d3` |
| Frozen model SHA256 | `206dadafc8d6cd96e21d838a52211d9b06d4a6ec541ea5c9a9ae8a6724ffbf5d` |
| Approved case manifest SHA256 | `57aa92f0a63bd2f8fe037904d0aecb2e2414031d5b9af8f08e5c9bbf73eddeba` |

## Session results

| Case | Label | PCAP SHA256 | EVE SHA256 | Events | SID alerts | Replay exit |
|---|---|---|---|---:|---:|---:|
| worker-attack-holdout-02-20261111 | Attack | `80b118068f89f0939d9a3c9ba72c977b08f95eff74a04e65b31cd548e0258f61` | `bfa08ee517c7e7c4ac7686c1dbe25ed4915cb3c52d70f09498fa66b2a9d573db` | 35 | 10 | 0 |
| worker-attack-holdout-03-20261111 | Attack | `837dd0b52f3472ce620baf9479f7f44da7515901455f54e2fe907277648a3343` | `a52c9e5644f3fdc9ada62d6c6956bed3c3442def17bdd5798394dac68cc970fe` | 35 | 10 | 0 |
| worker-normal-holdout-01-20261111 | Normal | `a4500b006908c26ffeed932244148c7372f2be2cb8abeb954cfe17ad3cda0fe7` | `c183882ae512f72539fc7396e953ee15fb7766676732621cf2040754360f9f39` | 34 | 9 | 0 |
| worker-normal-holdout-02-20261111 | Normal | `aad42d5710eb1006b76b744983744f47322137b2703126537b46787e34b01aaf` | `616798ca21c4012f8b211b75e3d69ee6b8933f24a8d7d4df83aacd3f58f8a0e6` | 34 | 9 | 0 |
| worker-normal-holdout-03-20261111 | Normal | `5a61ae059d8f25a2aa6bf1672f82d66c36f3e64de8d9d01dde6afca5081a2468` | `758eb6edd399433dcaa29d9f1dd536af4a8a32c6ef663441b6719f31fce0bc76` | 35 | 10 | 0 |

Session-level metrics are TP=2, FN=0, FP=3, TN=0, Precision=0.4000,
Recall=1.0000, F1=0.5714 and FPR=1.0000. The candidate is **REJECTED**.

All five Normal/Attack EVE files contained the candidate signature
`9103012`, message `ML REVIEW - SYN packet burst`, action `allowed` and
severity 3. This is an observed descriptive fact, not a basis for retuning
the frozen holdout or changing the candidate.

The failed false-positive gate prevented a replay signature and therefore
prevented owner approval, activation and deployment. No production state was
changed.
