# Candidate SID 9103012 lifecycle evidence

The new lineage run `lineage-new-generated-20261112-04` was registered locally
as a review-only candidate. This is a provenance record, not a replay
attestation, approval, or deployment.

| Field | Value |
|---|---|
| Candidate ID | `84ad314c885d821fb69713353134671cb355662a6effec1b890d59f38cada7e4` |
| Run / SID | `lineage-new-generated-20261112-04` / `9103012` |
| Rule SHA | `bd7ac80605988c5a35fa5180380b3f35c2b2870613cf20fa274a0fdd0fbd24d3` |
| Source rule file SHA | `d86c9222744bcf4aa88d2995354116a1149b772e3a5fe653d2d0ce3112af0e14` |
| Source metadata SHA | `3e8633330ff7080f0dc491b56c2cb9a144598082235c9e323d4b2ee2bc6a4704` |
| PCAP / model SHA | `7eb27fe774c8d889480662eaaea1e68b2336cc04c943ff06be399a24e4c0bbb5` / `206dadafc8d6cd96e21d838a52211d9b06d4a6ec541ea5c9a9ae8a6724ffbf5d` |
| Calibration / decision SHA | `814e17006c5cfee433477128e9d29abf7e403e28948d78a968c46c800b67e060` / `c7dffd3021d0c0195789e45c369f30108186753076b95586a2d80c9c744b579a` |
| Baseline rules SHA | `30d7a02cd85f7f7544231a91008a20dedbb15ff0e11ca388ac07aa8d564bf36b` |
| Candidate record SHA | `2bb34edcf09ee1474b3a4f1568b6b49273a37ed325674272ac49dd2c5d5114dd` |
| Audit chain SHA | `6c1e8313a0b2964d81351785e421db3a6e98968db52b902664f5750938d02bda` |

The record state is `PROPOSED`; `approved`, `deployable`, and `deployed` are
all false. SID collision checking against the copied VM1 ruleset passed.

The independently reviewed replay manifest is
`configs/suricata/isolated-candidate-9103012-independent-cases.json`, SHA-256
`57aa92f0a63bd2f8fe037904d0aecb2e2414031d5b9af8f08e5c9bbf73eddeba`. It fixes
the cohort at two independent Attack cases (02/03) and three Normal cases,
with Attack-01 explicitly excluded because it generated this rule. No missing
third Attack capture is synthesized.

## Validation status

The local workstation has no Suricata binary (`SURICATA_NOT_AVAILABLE`). The
independent replay inputs are present and hash-verified: attack-02
`80b118068f89f0939d9a3c9ba72c977b08f95eff74a04e65b31cd548e0258f61`, attack-03
`837dd0b52f3472ce620baf9479f7f44da7515901455f54e2fe907277648a3343`, and the
three Normal hashes already pinned in the baseline evidence. No syntax result,
EVE result, replay signature, owner approval, or activation result is claimed
for SID 9103012. Attack-01 remains the discovery PCAP and is excluded from the
independent Attack set.

The candidate operator derives a reviewed runtime identity from the candidate,
target `suricata-vm1`, loopback `lo`, and isolated-root scope. It binds live
probe hashes to signed replay cases. Any activation or rollback failure writes
a separate unsigned failure report containing the reason, best-effort
production-after snapshot, lifecycle audit count/hash, and cleanup status; it
cannot be interpreted as successful rollback evidence.

The existing Ed25519 lifecycle tests cover invalid/expired signatures, wrong
candidate/run provenance, host/interface gates, rollback failure, and activation
without approval. Candidate-specific tests additionally cover SID collision,
all bound hash fields, and signed replay evidence mismatch.
