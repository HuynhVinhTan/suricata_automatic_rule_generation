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

## 0. Candidate-specific trust-anchor rotation

The active frozen SID9103005 path uses a new, owner-reviewed replay signer.
Only its public fingerprint is committed:

`77af3ee89e4b7a1cbb99369b19e244b0be70a44dfc745ab77a926d9ad98a7b92`

The historical replay pin remains unchanged at
`b360fc9660513611a09287c9e6269c4bac4ac354ee85cecc0bbdbd4534f4d982` and is
not accepted by this G5 path. The historical owner pin remains
`92b2fb2fffa9da9ac82011fca030b4d5d822046c1fbe6c375ee08d5237cc4de7` for
historical workflows only. Active frozen G5 uses the candidate-specific owner
pin `6ac452b8966780e1dacd1b1d19f6c6a83de2c83d24b95c7e5a6ce7610fd13f63`.
The owner public key is stored outside the repository using this Windows
convention:

`%LOCALAPPDATA%\SuricataAI\keys\g5-owner-9103005\owner.pem`

`%LOCALAPPDATA%\SuricataAI\keys\g5-owner-9103005\owner.pub.pem`

Replay, owner and runtime signing roles must be independent. The independent
runtime signer fingerprint used by the owner authorization is
`35050afe9d85194fff5c889601ff8a3cab35b717e2edc42e1bac69bc6abd0c44`.
The runtime key is bound to the signed owner authorization and cannot equal
either other role.

The new replay private/public files are provisioned on VM1 at:

`/home/tanhv/.config/suricata-ai/g5-replay-9103005/replay.pem`

`/home/tanhv/.config/suricata-ai/g5-replay-9103005/replay.pub.pem`

Never copy the replay private key into Git, `.runtime-staging/`, an archive or
the owner workstation. The existing signed replay attestation
`73a81eb8ef2c99a324ce1f720125d8b1f12eef50c0cd6b390efc5defc78f4989` remains
the verified evidence for candidate `bfd6891a14dd3e648737e0a43d20f602d160085cefc92aa5f7fcfa8d32e0f1f6`;
do not regenerate or edit it unless the signed evidence itself changes.

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

## 2. Prepare replay evidence from existing native artifacts

Prepare the unsigned replay record from the already verified native report,
cohort receipts, frozen metadata and exact candidate. This command never
collects a holdout or invents a success marker; it refuses changed labels,
hashes, run IDs, calibration provenance or incomplete capture/handoff evidence:

```powershell
python -m scripts.prepare_frozen_rst_replay `
  --candidate C:\g5-signed\sid9103005-candidate.json `
  --freeze "$dev\acceptance-freeze.json" `
  --development-evidence "$dev\development-evidence.json" `
  --holdout-report "$holdout\native-holdout-replay.json" `
  --cohort-results "$holdout\cohort-results.json" `
  --cohort-plan "$holdout\cohort-plan.json" `
  --rule "$dev\ml-generated-rst.rules" `
  --metadata "$dev\ml-generated-rst.metadata.json" `
  --source-commit c3aaa982fcb2d38b71d51ac9ae2af8a41b3e1dad `
  --freeze-sha256 74ce643d782d525e83910138b32218bc69e8d97a6908e725f71dbbeab0fd9bd4 `
  --cohort-sha256 443b42478b3bfbc0d66433fc5e582433426962fe54427278b584a5e5e859efaa `
  --output C:\g5-signed\sid9103005-replay-evidence.json
```

The output is explicitly unsigned, review-only evidence. It contains all six
cohort probes, their labels and hashes, the native syntax/production proof, and
the threshold derived from frozen development metadata.

## 3. Independent signed replay attestation

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

The CLI enforces the candidate-specific replay fingerprint in
`src/netids/key_pins.py` and checks that the encrypted private key matches that
public key. The historical replay fingerprint is rejected here. The private
key must never enter Git, `.runtime-staging/`, or VM transfer bundles.

## 4. Separate owner authorization

The owner reviews the exact candidate ID, freeze/cohort/baseline hashes, target,
loopback interface, and mandatory rollback. The command prompts for the exact
authorization phrase and the encrypted owner-key passphrase:

```powershell
python -m scripts.approve_frozen_rst_activation `
  --candidate C:\g5-signed\sid9103005-candidate.json `
  --replay-attestation C:\g5-signed\sid9103005-replay-attestation.json `
  --replay-public C:\keys\g5-replay-9103005.pub.pem `
  --owner-private $env:LOCALAPPDATA\SuricataAI\keys\g5-owner-9103005\owner.pem `
  --owner-public $env:LOCALAPPDATA\SuricataAI\keys\g5-owner-9103005\owner.pub.pem `
  --runtime-public C:\keys\g5-runtime-9103005.pub.pem `
  --isolated-root /home/tanhv/suricata-rule-review/isolated-lifecycle-9103005 `
  --runtime-id suricata-vm1:isolated-lifecycle-9103005:lo `
  --target-vm suricata-vm1 `
  --interface lo `
  --approver-identity OWNER_ID `
  --output C:\g5-signed\sid9103005-owner-authorization.json
```

The owner public key must satisfy the candidate-specific frozen G5 owner
fingerprint; the historical owner pin is rejected on this path. The new replay
public key must satisfy the candidate-specific G5 pin, never the historical
replay pin. The runtime public key must be a third, independent role, and its
fingerprint is bound into the owner authorization; the VM command must use the
matching encrypted runtime private key. The resulting authorization is
one-shot, nonce-bound, expiry-checked, and scoped to the candidate-specific
isolated root and 300-second maximum operation. Mismatched anchors are rejected
before lifecycle staging or activation.

## 5. VM1 runtime and rollback

Transfer only the candidate JSON, signed replay attestation, owner authorization,
the three public keys, the isolated YAML, and the encrypted runtime signing key to
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
  --runtime-public /home/tanhv/.config/suricata-ai/g5-runtime-9103005.pub.pem \
  --production-yaml /etc/suricata/suricata.yaml \
  --production-rules /var/lib/suricata/rules/suricata.rules \
  --isolated-yaml /home/tanhv/suricata-rule-review/isolated-lifecycle-9103005/isolated.yaml \
  --isolated-root /home/tanhv/suricata-rule-review/isolated-lifecycle-9103005 \
  --probe A1=/ABSOLUTE/VERIFIED/A1.pcap \
  --probe A2=/ABSOLUTE/VERIFIED/A2.pcap \
  --probe A3=/ABSOLUTE/VERIFIED/A3.pcap \
  --probe N1=/ABSOLUTE/VERIFIED/N1.pcap \
  --probe N2=/ABSOLUTE/VERIFIED/N2.pcap \
  --probe N3=/ABSOLUTE/VERIFIED/N3.pcap \
  --audit-path /home/tanhv/suricata-rule-review/isolated-lifecycle-9103005/audit/owner-once.jsonl \
  --runtime-private /home/tanhv/.config/suricata-ai/g5-runtime-9103005.pem \
  --evidence-output /home/tanhv/g5-signed/sid9103005-runtime-evidence.json \
  --failure-output /home/tanhv/g5-signed/sid9103005-runtime-failure.json
```

Before any VM1 execution, an owner must stage the reviewed source commit as a
new versioned archive and verify its hash. This is the exact archive command
for the current branch after the commit is known; it is a staging instruction,
not an execution record:

```bash
FINAL_RELEASE_COMMIT="<reviewed-commit-sha>"
ARCHIVE="suricata-ai-tools-${FINAL_RELEASE_COMMIT}.tar"
git archive --format=tar --prefix="suricata-ai-tools-${FINAL_RELEASE_COMMIT}/" \
  --output="$ARCHIVE" "$FINAL_RELEASE_COMMIT"
sha256sum "$ARCHIVE"
scp -o BatchMode=yes -o StrictHostKeyChecking=yes "$ARCHIVE" \
  "suricata-vm1:/home/tanhv/.runtime-staging/g5-source-${FINAL_RELEASE_COMMIT}/source.tar"
```

On VM1, verify the copied archive SHA256 before extracting into a fresh,
versioned release directory. The existing checkout, production configuration,
`.runtime-staging/`, and historical evidence remain untouched. Do not execute
the runtime command until the fresh replay attestation, owner authorization and
the staged source commit all refer to the same reviewed candidate workflow.

`/ABSOLUTE/VERIFIED/*.pcap` tokens must be replaced only with paths whose bytes
match the signed six-case cohort. The command refuses guessed, substituted,
duplicated or relabeled PCAPs. It requires Suricata 8.0.3, VM1
hostname/interface, an isolated `-S` ruleset, candidate loading, all three
Attack alerts, zero Normal/negative-control alerts, mandatory rollback,
post-rollback zero candidate alerts, child-process cleanup, a trusted runtime
signature, an effective 300-second deadline, and byte-identical production
before/after snapshots. It never calls systemd or writes production rules.

Any failure, including rollback failure or production mutation, is FAILED/
UNVERIFIED. Preserve the failure JSON and isolated logs; do not reuse the
authorization or delete the audit ledger.
