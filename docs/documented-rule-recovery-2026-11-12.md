# SID 9103003 documented-frozen-rule recovery

Read-only searches on Windows, VM1 and VM3 did not recover the original
`ml-generated-rst.rules` or `ml-generated-rst.metadata.json`. The matching VM1
file `isolated-vm3-rulegen-v02/rst-candidate.rules` is explicitly rejected: it
uses `flags:R` and threshold 2, not the accepted `flags:R+` and threshold 3.

The accepted rule was recovered only from the unchanged committed Git evidence
document `artifacts/milestones-4-6-acceptance-20261112/evidence.md`, after
verifying:

- Git blob: `4f61d7829ec566c4084444904c6e3bf5955e3f5f`
- Source document SHA-256: `e9d17a8874576ab0a579b15897abe0562d412d624907f6548acae2fb0f788dac`
- Canonical rule-text SHA-256 excluding terminal LF: `7182bb328ce4ed1230c6de9b20c825d458b8c224a494d6b2a60063cca5ec21df`
- Historical generated metadata: **unavailable; not recovered**

The recovery record is deliberately classified as
`documented_frozen_rule_recovery`; it is not original generator provenance.
The replay attestor requires this class, the pinned Git blob and source hash,
then performs independent Suricata syntax and six-PCAP EVE validation before
it can sign. Missing, modified or contradictory evidence fails closed.

The recovery helper is [recover_documented_frozen_rule.py](../scripts/recover_documented_frozen_rule.py), and the pinned replay input is [isolated-lifecycle-9103003-replay-manifest.json](../configs/suricata/isolated-lifecycle-9103003-replay-manifest.json).

## Real offline replay evidence

VM1 created the dedicated root
`/home/tanhv/suricata-rule-review/isolated-lifecycle-9103003` and ran
Suricata 8.0.3 `-T` plus six independent `-r` processes. The recovered rule
file SHA-256 including terminal LF was
`1280d0a9acdf0d6f90a5f81e6926a722a3bf7cdb502e0b3c4f1f4cc5e054bdfd`; the
manifest SHA-256 was
`4c513ab9cec1e5e347301066f9a7d28f822f44e8119b086fe188a020497f8f9c`; and the
isolated YAML SHA-256 was
`982f477468d4f02d1373484720081662859e02420205916dcf9923c6b15385e3`.

| Case | EVE SHA-256 | EVE events | SID 9103003 alerts |
|---|---|---:|---:|
| Attack 01 | `78dc8bdb0627d790268a594d6da51e68df2147f709fa7ec093f0ff0f02fc37de` | 33 | 8 |
| Attack 02 | `24141b3a0017813e96251542e4d4350f3ffb109ec4bea233c5bc01b5d2e555e2` | 33 | 8 |
| Attack 03 | `edaff1e1bdfe9b1a4eccb1605743a13108823a6eb66cbf38e595042ba7b1c3ab` | 33 | 8 |
| Normal 01 | `7d2bf316959c50d633052dcdfa82bc0dbfea5891b9da85603af10b023606912b` | 25 | 0 |
| Normal 02 | `2b749b401870dc7307b1ccaac4a24dcd7ae709b7fcd2d9b728445f70b3a7ce3d` | 25 | 0 |
| Normal 03 | `330c5f1eb3b96c325d8e400c7f50f111fa35335c201ae72ec236d2e7c86e3b51` | 25 | 0 |

These observations were followed by a real VM1 Ed25519 replay attestation.
The attestation SHA-256 is
`aaab81a187dc0640cc73bb05fe4ce2feda93b1be9af21922bcf532d15573c5ce` and
independent verification with the pinned replay public key passed. No owner
approval was generated and no live activation was attempted. `tcpreplay` is
absent on VM1, so the loopback activation gate is blocked independently of the
successful offline `-r` replays.
