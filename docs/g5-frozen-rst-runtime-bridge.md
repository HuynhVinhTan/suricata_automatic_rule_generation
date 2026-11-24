# G5 frozen SID9103005 runtime bridge

This is the candidate-specific G5 path for the already verified frozen RST
candidate. It uses `g5_frozen_rst_candidate_v1`,
`g5_frozen_rst_replay_attestation_v1`, and
`g5_frozen_owner_authorization_v1`. The historical `candidate_record_v1`
path and its hard-coded historical manifest remain unchanged.

The bridge binds all of the following into the candidate ID:

- SID9103005, the canonical rule-content SHA256, and the full rule-file SHA256;
- the freeze SHA256
  `74ce643d782d525e83910138b32218bc69e8d97a6908e725f71dbbeab0fd9bd4`;
- the cohort-results SHA256
  `443b42478b3bfbc0d66433fc5e582433426962fe54427278b584a5e5e859efaa`;
- the native holdout report SHA256 and the exact six-case identity/digest;
- the baseline rules SHA256
  `30d7a02cd85f7f7544231a91008a20dedbb15ff0e11ca388ac07aa8d564bf36b`;
- the complete baseline comparison evidence hash.

The bridge remains review-only. It does not claim Hybrid equivalence or
production suitability. Legitimate repeated RST traffic outside the tested
Normal distribution remains a residual risk.

## 1. Read-only candidate import

Run from the repository checkout. This reads the existing evidence and writes a
new candidate envelope only; it does not alter `.runtime-staging/` or VM state:

```powershell
$repo = 'D:\suricata-ai-project-worktrees\feat-complete-suricata-ai-e2e'
$dev = Join-Path $repo '.runtime-staging\g4-rst-dev-20261124T075112Z-9d0b815b'
$holdout = Join-Path $repo '.runtime-staging\g4-holdout-20261124T084145Z-fd9f2786'
$g5 = Join-Path $repo '.runtime-staging\g5-baseline-sid9103005'
$out = Join-Path $repo 'g5-signed\sid9103005-candidate.json'
$env:PYTHONPATH = Join-Path $repo 'src'
python -m scripts.register_frozen_rst_candidate `
  --freeze "$dev\acceptance-freeze.json" `
  --development-evidence "$dev\development-evidence.json" `
  --holdout-report "$holdout\native-holdout-replay.json" `
  --cohort-results "$holdout\cohort-results.json" `
  --cohort-plan "$holdout\cohort-plan.json" `
  --rule "$dev\ml-generated-rst.rules" `
  --metadata "$dev\ml-generated-rst.metadata.json" `
  --baseline-comparison "$g5\baseline-comparison.json" `
  --source-commit c3aaa982fcb2d38b71d51ac9ae2af8a41b3e1dad `
  --freeze-sha256 74ce643d782d525e83910138b32218bc69e8d97a6908e725f71dbbeab0fd9bd4 `
  --cohort-sha256 443b42478b3bfbc0d66433fc5e582433426962fe54427278b584a5e5e859efaa `
  --baseline-sha256 30d7a02cd85f7f7544231a91008a20dedbb15ff0e11ca388ac07aa8d564bf36b `
  --output $out
```

The output must report `schema_version=g5_frozen_rst_candidate_v1`,
`sid=9103005`, the rule SHA
`171c1405ad7019feebf588039a1479ceb70a3596b607e1ff122bb87667babb49`, and
`approved=false`, `deployed=false`.
With the supplied baseline comparison bytes, the expected candidate ID is
`bfd6891a14dd3e648737e0a43d20f602d160085cefc92aa5f7fcfa8d32e0f1f6`.

## 2. Independent signed replay attestation

The trusted replay signer must create a new JSON evidence file containing the
exact candidate binding, six cohort cases, syntax proof, candidate-loaded
proof, Attack/Normal/negative-control results, zero Normal and negative-control
false positives, and unchanged-production proof. It must not be hand-edited
from a different manifest. Sign it with the independently provisioned replay
key:

```powershell
python -m scripts.attest_frozen_rst_replay `
  --candidate C:\g5-signed\sid9103005-candidate.json `
  --evidence C:\g5-signed\sid9103005-replay-evidence.json `
  --replay-private C:\keys\g5-replay-9103005.pem `
  --replay-public C:\keys\g5-replay-9103005.pub.pem `
  --output C:\g5-signed\sid9103005-replay-attestation.json
```

The public key must satisfy the pinned replay fingerprint in
`src/netids/key_pins.py`; the private key must never enter Git, `.runtime-staging/`,
or VM transfer bundles.

## 3. Separate owner authorization

The owner reviews the exact candidate ID, freeze/cohort/baseline hashes, target,
loopback interface, and mandatory rollback. The command prompts for the exact
authorization phrase and the encrypted owner-key passphrase:

```powershell
python -m scripts.approve_frozen_rst_activation `
  --candidate C:\g5-signed\sid9103005-candidate.json `
  --replay-attestation C:\g5-signed\sid9103005-replay-attestation.json `
  --replay-public C:\keys\g5-replay-9103005.pub.pem `
  --owner-private C:\keys\g5-owner-9103005.pem `
  --owner-public C:\keys\g5-owner-9103005.pub.pem `
  --isolated-root /home/tanhv/suricata-rule-review/isolated-lifecycle-9103005 `
  --runtime-id suricata-vm1:isolated-lifecycle-9103005:lo `
  --target-vm suricata-vm1 `
  --interface lo `
  --approver-identity OWNER_ID `
  --output C:\g5-signed\sid9103005-owner-authorization.json
```

The owner public key must satisfy the pinned owner fingerprint. The resulting
authorization is one-shot, nonce-bound, expires after 15 minutes, and is scoped
to the candidate-specific isolated root and 300-second maximum operation.

## 4. VM1 runtime and rollback

Transfer only the candidate JSON, signed replay attestation, owner authorization,
both public keys, the isolated YAML, and the encrypted runtime signing key to
VM1. Never transfer either owner or replay private key. Use the actual six
reviewed PCAP paths only after read-only SHA256 checks against the cohort report.
The repository evidence contains the hashes but intentionally does not contain
private PCAP paths, so a path token must not be guessed.

The runtime command is:

```bash
python3 -m scripts.operate_frozen_rst_once \
  --candidate /home/tanhv/g5-signed/sid9103005-candidate.json \
  --replay /home/tanhv/g5-signed/sid9103005-replay-attestation.json \
  --owner-authorization /home/tanhv/g5-signed/sid9103005-owner-authorization.json \
  --replay-public /home/tanhv/.config/suricata-ai/g5-replay-9103005.pub.pem \
  --owner-public /home/tanhv/.config/suricata-ai/g5-owner-9103005.pub.pem \
  --production-yaml /etc/suricata/suricata.yaml \
  --production-rules /var/lib/suricata/rules/suricata.rules \
  --isolated-yaml /home/tanhv/suricata-rule-review/isolated-lifecycle-9103005/isolated.yaml \
  --isolated-root /home/tanhv/suricata-rule-review/isolated-lifecycle-9103005 \
  --attack-pcap /ABSOLUTE/VERIFIED/A1.pcap \
  --attack-sha256 490016e1e33b07c10f4035eb0425d6e2427f814fd9da6ea9694dfd020c00b07e \
  --normal-pcap /ABSOLUTE/VERIFIED/N1.pcap \
  --normal-sha256 58ad0bd5150c5fa7c56ea9c9531fda2e2240b84c0c1b0bc083bd0f311b5c4c0e \
  --negative-pcap /ABSOLUTE/VERIFIED/N2.pcap \
  --negative-sha256 7af0d4524dec3c08c2bce4787cb329c568e3cac3e46e6d9e39e766814936dcdf \
  --negative-pcap /ABSOLUTE/VERIFIED/N3.pcap \
  --negative-sha256 85075147568ba52ebcae87c70727910d3839c22b34e56da976c843e25a8acf12 \
  --audit-path /home/tanhv/suricata-rule-review/isolated-lifecycle-9103005/audit/owner-once.jsonl \
  --runtime-private /home/tanhv/.config/suricata-ai/g5-runtime-9103005.pem \
  --evidence-output /home/tanhv/g5-signed/sid9103005-runtime-evidence.json \
  --failure-output /home/tanhv/g5-signed/sid9103005-runtime-failure.json
```

`/ABSOLUTE/VERIFIED/*.pcap` tokens must be replaced only with paths whose bytes
match the printed hashes. The command refuses guessed or changed PCAPs. It
requires Suricata 8.0.3, VM1 hostname/interface, an isolated `-S` ruleset,
candidate loading, real Attack alerts, zero Normal and negative-control alerts,
mandatory rollback, post-rollback zero candidate alerts, child-process cleanup,
and byte-identical production before/after snapshots. It never calls systemd or
writes production rules.

Any failure, including rollback failure or production mutation, is FAILED/
UNVERIFIED. Preserve the failure JSON and isolated logs; do not reuse the
authorization or delete the audit ledger.
