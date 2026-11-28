# G1/G2/G3/G4/G6 Runtime Authorization Matrix

This is the single owner-approval package for the reviewed three-VM lab. It is
not approval to execute. No SSH, sudo, timer, capture, traffic, key,
inference, or Suricata operation has been performed while preparing it.

## Fixed identities and boundaries

| Host | Identity | Scope |
|---|---|---|
| VM1 | `tanhv@192.168.10.10`, `ens33` | bounded native capture only; no production service change |
| VM2 | `kali@192.168.10.20` | lab generators and private G3 signing key only |
| VM3 | `tanhv@192.168.10.30` | verified inbox, frozen five-feature worker, G3 public key/SQLite, review-only G6 |

Traffic is only VM2 `192.168.10.20` to VM1 `192.168.10.10`. G6 uses existing
EVE shadow input and creates no traffic. `tcpreplay`, loopback injection,
production activation, sudoers changes, model retuning, timer services, and
PR merging are excluded.

The controlling host for orchestration is the Windows owner workstation,
using PowerShell and the checked-out worktree
`D:\suricata-ai-project-worktrees\feat-complete-suricata-ai-e2e`. VM2 and VM3
are SSH targets; neither VM runs the Windows launcher or self-SSHes.

## G1 read-only provenance gate

Run these checks on each VM before any capture or inference:

```bash
hostname -f; id; ip -br addr; findmnt -T /; df -B1 -P /; df -i /
```

VM1 is an unversioned deployment. Do not run `git rev-parse` there:

```bash
ROOT=/home/tanhv/suricata-ai-tools
test ! -d "$ROOT/.git"
readlink -e "$ROOT/backend/pcap_capture.py"
readlink -e "$ROOT/backend/pcap_handoff.py"
stat -c '%U:%G %a %F %n' "$ROOT/backend/pcap_capture.py" "$ROOT/backend/pcap_handoff.py"
sha256sum "$ROOT/backend/pcap_capture.py" "$ROOT/backend/pcap_handoff.py"
cd "$ROOT"
PYTHONPATH=. /usr/bin/python3 -c \
  'import backend.pcap_capture as m; print(m.__file__)'
```

The deployed capture module must match the independently reviewed lineage
`ac40a8759ca64e0780f5e3015af3fef7843e4ff3` and hash
`622f1d278a0b62f8db40ee1b4b1a7cd4fc7643f0ea3c6dcf2826d36b1140d787`.

VM2’s historical generator is fixed to:

```bash
GEN=/home/kali/suricata-ai-showcase/releases/a8fe3e82e701beafc9e47fb7bc5b45064029f8be/scripts/lab_slow_port_scan.py
readlink -e "$GEN"; sha256sum "$GEN"
```

Expected generator hash:
`2acb5c56974d81e1fee8e57238ee6809c0be6cb847a9dd399be251da96bb8b09`.

The frozen G4 artifact gate is:

```bash
MODEL="$VM3_PRIVATE_ROOT/lab-models/lab_syn_anomaly_v0_1/models.joblib"
sha256sum "$MODEL"
```

The expected model, calibration, and decision hashes are respectively:

```text
206dadafc8d6cd96e21d838a52211d9b06d4a6ec541ea5c9a9ae8a6724ffbf5d
814e17006c5cfee433477128e9d29abf7e403e28948d78a968c46c800b67e060
c7dffd3021d0c0195789e45c369f30108186753076b95586a2d80c9c744b579a
```

`VM3_PRIVATE_ROOT` is not guessed. The owner must derive one absolute,
non-symlink private root during read-only inspection and prove that the model,
reference CSVs, calibration, proposal, candidate, and worker output all remain
under it. If no single root satisfies this, G4 stops.

## Versioned G3 source synchronization

The reviewed archive was generated on the controlling Windows host from the
verified repository commit below. The VMs are not assumed to be Git checkouts;
each VM uses its own home-directory release root and the extracted source
layout is checked directly.

```bash
FINAL_RELEASE_COMMIT="156d4afe19c87172896c34e666dfbfeca7c0d215"
git archive --format=tar --prefix="suricata-ai-tools-${FINAL_RELEASE_COMMIT}/" \
  "$FINAL_RELEASE_COMMIT" | sha256sum
```

Approved archive SHA256 for that exact prefix is
`7c2846d0342569faa9afa92187dc087a9298ed51bb5d38a3deb71cd99fd16951`.
The archive contains no private or public key. If VM2 or VM3 lacks the
reviewed G3 modules, transfer the archive to a temporary path, verify its
SHA256, extract only into a new versioned release directory, verify the
complete file manifest, and leave that VM's `current` pointer unchanged. A
failed extraction leaves the old release and pointer untouched; no automatic
retry or cleanup is performed.

Read-only VM2 checks use `/home/kali` only:

```bash
FINAL_RELEASE_COMMIT="156d4afe19c87172896c34e666dfbfeca7c0d215"
RELEASE="/home/kali/suricata-ai-showcase/releases/$FINAL_RELEASE_COMMIT"
test -d "$RELEASE"; test ! -L "$RELEASE"
find "$RELEASE" -xdev -type f -print0 | sort -z | xargs -0 sha256sum
test -f "$RELEASE/src/netids/lifecycle_ed25519.py"
sha256sum "$RELEASE/src/netids/lifecycle_ed25519.py"
PYTHONPATH="$RELEASE/src" /usr/bin/python3 -c \
  'import netids.lifecycle_ed25519 as m; print(m.__file__)'
```

Read-only VM3 checks use `/home/tanhv` only:

```bash
FINAL_RELEASE_COMMIT="156d4afe19c87172896c34e666dfbfeca7c0d215"
RELEASE="/home/tanhv/suricata-ai-showcase/releases/$FINAL_RELEASE_COMMIT"
test -d "$RELEASE"; test ! -L "$RELEASE"
find "$RELEASE" -xdev -type f -print0 | sort -z | xargs -0 sha256sum
test -f "$RELEASE/src/netids/lifecycle_ed25519.py"
sha256sum "$RELEASE/src/netids/lifecycle_ed25519.py"
PYTHONPATH="$RELEASE/src" /usr/bin/python3 -c \
  'import netids.lifecycle_ed25519 as m; print(m.__file__)'
```

The actual G3 entrypoint paths, if present in either versioned tree, are
checked without assuming a checkout:

```bash
for p in "$RELEASE/scripts/g3_lab_provision_key.py" \
         "$RELEASE/scripts/g3_lab_sign.py" \
         "$RELEASE/scripts/g3_lab_verify.py" \
         "$RELEASE/src/netids/g3_lab_demo.py" \
         "$RELEASE/src/netids/g3_lab_cli.py"; do
  test -f "$p" || { echo "missing reviewed G3 path: $p" >&2; exit 1; }
  readlink -e "$p"; stat -c '%U:%G %a %F %n' "$p"; sha256sum "$p"
done
```

The deployed release roots are distinct:

```text
VM2_RELEASE_ROOT=/home/kali/suricata-ai-showcase
VM3_RELEASE_ROOT=/home/tanhv/suricata-ai-showcase
```

No VM command uses `git rev-parse`, and no VM path is inferred from the other
VM's home directory.

G3 fingerprint verification is over the raw Ed25519 public-key bytes, never
the PEM container's `sha256sum`. VM2 computes the value with the reviewed
function; VM3 recomputes it independently from the received public key. The
pinned file is accepted only if it contains exactly one line consisting of
the matching 64-character hexadecimal fingerprint:

```bash
PUB=/home/kali/suricata-ai-showcase/private/g3/g3-signer.pub.pem
PYTHONPATH="$RELEASE/src" PUB="$PUB" /usr/bin/python3 -c \
  'import os; from pathlib import Path; from netids.lifecycle_ed25519 import public_key_fingerprint; print(public_key_fingerprint(Path(os.environ["PUB"]).read_bytes()))'
```

On VM3, after the public key is independently received and hash-checked:

```bash
PUB=/home/tanhv/suricata-ai-showcase/private/g3/g3-signer.pub.pem
PIN=/home/tanhv/suricata-ai-showcase/private/g3/g3-signer.pub.sha256
FINGERPRINT="$(PYTHONPATH="$RELEASE/src" PUB="$PUB" /usr/bin/python3 -c \
  'import os; from pathlib import Path; from netids.lifecycle_ed25519 import public_key_fingerprint; print(public_key_fingerprint(Path(os.environ["PUB"]).read_bytes()))')"
PINNED="$(cat "$PIN")"
test "$(wc -l < "$PIN")" -eq 1
test "${#PINNED}" -eq 64
case "$PINNED" in *[!0123456789abcdefABCDEF]*) exit 1;; esac
test "$PINNED" = "$FINGERPRINT"
```

`sha256sum "$PUB"` may be used separately for transfer integrity, but it is
not the G3 trust fingerprint. The private key remains exclusively on VM2.

## G2: one VM1 oneshot capture and one VM2 generator

The existing unit remains unchanged:

```text
/etc/systemd/system/suricata-ai-capture.service
SHA256 42e055539653c06646d786ac7a4888d5426d7d7e6fe0eb1e0dcd11bbdc4f25de
```

The unit is `Type=oneshot`. Readiness therefore requires:

```text
ActiveState=activating
SubState=start
/usr/bin/tcpdump -i ens33 -s 262144 -n -U -w "$pcap" \
  "tcp and src host 192.168.10.20 and dst host 192.168.10.10"
```

The reviewed readiness script starts with `systemctl start --no-block`, checks
the actual tcpdump command line, enforces the 60-second capture window, and
rejects `inactive`, `failed`, `active/exited`, missing process, or deadline
states. It prints `G2_CAPTURE_READY=TRUE` only on the positive gate.

Generate fresh values immediately before the single invocation. Run this exact
command on the Windows controlling host, in PowerShell, from the feature
worktree; do not run it inside VM2 and do not paste a generated script into a
here-string:

```powershell
$Repo = 'D:\suricata-ai-project-worktrees\feat-complete-suricata-ai-e2e'
$Python = 'C:\Python313\python.exe'
Set-Location $Repo
$g2RunId = (& $Python -c 'from datetime import datetime,timezone; import secrets; print("g2-live-attack-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(8))').Trim()
$g2Seed = (& $Python -c 'from datetime import datetime,timezone; print(datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"))').Trim()
$g2Out = "/home/kali/suricata-ai-showcase/evidence/live/$g2RunId"
& $Python -m scripts.g2_live_generator_launcher --run-id $g2RunId --seed $g2Seed --output-dir $g2Out --execute --capture-ready-confirmed --owner-authorized
if ($LASTEXITCODE -ne 0) { throw "G2 launcher failed with exit code $LASTEXITCODE" }
```

The launcher creates exactly one SSH argv targeting `kali@192.168.10.20` and
one remote Bash script. Its `--execute` guard is valid only after independent
VM1 readiness and owner authorization have been recorded.

Limits are one invocation, one exclusive VM2 evidence directory, 24 ports
`18100–18123`, interval `2.0`, timeout `1.0`, 60-second VM1 capture, full
snaplen `262144`, and 64 MiB maximum PCAP. A failure preserves all partial
evidence and stops; it is not retried.

## G3: evidence-derived signing and verification

The native handoff remains byte-oriented:

```text
/home/tanhv/suricata-ai-outbox/$capture_id/$capture_id.pcap
/home/tanhv/suricata-ai-outbox/$capture_id/$capture_id.manifest.json
/home/tanhv/suricata-ai-outbox/$capture_id/$capture_id.ready.json
```

The reviewed `g3-lab-build-record` operation validates the actual PCAP bytes,
the native manifest’s raw file SHA256, the ready marker’s matching raw digest,
and the generator JSON’s independently recorded SHA256 before constructing a
separate `review_only=true` canonical manifest. The signed record binds:
capture ID, separate G3 run/event IDs, source/destination identities, PCAP
hash, generator hash, native raw-manifest hash, canonical G3-manifest hash,
and verified timestamps. The two manifest hashes are never substituted.

Because the private key remains on VM2, the sealed native bundle and the VM2
generator JSON are copied once into the exclusive VM2 G3 input directory using
strict SCP, preserving the three original capture filenames and verifying all
three hashes before record construction. The VM1 originals are never removed
or renamed.

With the actual `capture_id` read from the sealed manifest and a fresh
`generator_id`, VM2 constructs and signs the record as follows:

```bash
g3_input="/home/kali/suricata-ai-showcase/evidence/g3/input/$capture_id"
pcap="$g3_input/$capture_id.pcap"
native_manifest="$g3_input/$capture_id.manifest.json"
ready_marker="$g3_input/$capture_id.ready.json"
generator_json="/home/kali/suricata-ai-showcase/evidence/g4/$generator_id/generator.json"
test -f "$pcap" -a -f "$native_manifest" -a -f "$ready_marker" -a -f "$generator_json"
g3_record="/home/kali/suricata-ai-showcase/evidence/g3/record.json"
g3_run_id="g3-${capture_id}"
event_id="g3-event-${generator_id}"
nonce="$(openssl rand -hex 32)"
pcap_sha256="$(sha256sum "$pcap" | awk '{print $1}')"
generator_sha256="$(sha256sum "$generator_json" | awk '{print $1}')"
PYTHONPATH="$RELEASE/src" /usr/bin/python3 "$RELEASE/scripts/g3_lab_build_record.py" \
  --capture-id "$capture_id" --generator-id "$generator_id" \
  --pcap "$pcap" --native-manifest "$native_manifest" \
  --ready-marker "$ready_marker" --generator-json "$generator_json" \
  --expected-pcap-sha256 "$pcap_sha256" \
  --expected-generator-sha256 "$generator_sha256" \
  --g3-run-id "$g3_run_id" --event-id "$event_id" --sequence 0 \
  --nonce "$nonce" --output "$g3_record"
PYTHONPATH="$RELEASE/src" /usr/bin/python3 "$RELEASE/scripts/g3_lab_sign.py" \
  --input-record "$g3_record" \
  --private-key /home/kali/suricata-ai-showcase/private/g3/g3-signer.pem \
  --output /home/kali/suricata-ai-showcase/evidence/g3/envelope.json
```

The owner types the private-key passphrase locally. It is never supplied as a
command argument or transferred.

Public-key and envelope transfer are separate, hash-checked operations:

```bash
PUB=/home/kali/suricata-ai-showcase/private/g3/g3-signer.pub.pem
scp -B "$PUB" tanhv@192.168.10.30:/home/tanhv/suricata-ai-showcase/private/g3/g3-signer.pub.pem.partial
ssh tanhv@192.168.10.30 'set -eu; test ! -e /home/tanhv/suricata-ai-showcase/private/g3/g3-signer.pub.pem; sha256sum /home/tanhv/suricata-ai-showcase/private/g3/g3-signer.pub.pem.partial; ln -T -- /home/tanhv/suricata-ai-showcase/private/g3/g3-signer.pub.pem.partial /home/tanhv/suricata-ai-showcase/private/g3/g3-signer.pub.pem'
ssh tanhv@192.168.10.30 'set -eu; R=/home/tanhv/suricata-ai-showcase/releases/156d4afe19c87172896c34e666dfbfeca7c0d215; PUB=/home/tanhv/suricata-ai-showcase/private/g3/g3-signer.pub.pem; PIN=/home/tanhv/suricata-ai-showcase/private/g3/g3-signer.pub.sha256; test ! -e "$PIN"; FINGERPRINT="$(PYTHONPATH="$R/src" PUB="$PUB" /usr/bin/python3 -c '\''import os; from pathlib import Path; from netids.lifecycle_ed25519 import public_key_fingerprint; print(public_key_fingerprint(Path(os.environ["PUB"]).read_bytes()))'\'')"; test "${#FINGERPRINT}" -eq 64; case "$FINGERPRINT" in *[!0123456789abcdefABCDEF]*) exit 1;; esac; umask 077; printf "%s\n" "$FINGERPRINT" > "$PIN"'
scp -B /home/kali/suricata-ai-showcase/evidence/g3/envelope.json tanhv@192.168.10.30:/home/tanhv/suricata-ai-showcase/evidence/g3/envelope.json.partial
ssh tanhv@192.168.10.30 'set -eu; test ! -e /home/tanhv/suricata-ai-showcase/evidence/g3/envelope.json; ln -T -- /home/tanhv/suricata-ai-showcase/evidence/g3/envelope.json.partial /home/tanhv/suricata-ai-showcase/evidence/g3/envelope.json'
```

The owner independently compares the VM2 fingerprint output with the VM3
fingerprint file before running verification. Any pre-existing destination,
hash mismatch, symlink, or partial transfer stops the operation.

VM2 signs with `g3_lab_sign.py`; only the public key, record, and envelope are
transferred to VM3. VM3 verifies with `g3_lab_verify.py` and:

```text
/home/tanhv/suricata-ai-showcase/private/g3/g3-replay.sqlite3
```

The SQLite ledger uses `BEGIN IMMEDIATE`, `synchronous=FULL`, unique nonce,
run, event, and envelope constraints. The same envelope is checked again
after reopening the database and must fail as replay. Wrong-key, missing
`review_only`, native raw-digest mismatch, canonical-digest mismatch, PCAP
mismatch, and tampered-generator cases are fail-closed tests.

## G4: three Attack and three Normal sessions

Run six independent sequences. Each sequence has its own capture readiness,
capture ID, generator ID, exclusive generator directory, sealed bundle, raw
hashes, and VM3 worker output. Correlation requires matching source/destination
identities, five-tuples, packet/SYN counts, generator attempt count, timestamp
order (`generator start <= generator end <= capture sealed`), PCAP hash, native
manifest hash, ready-marker hash, and generator hash.

Attack uses 24 unique ports `18100–18123`, VM2 source `192.168.10.20`, VM1
destination `192.168.10.10`, interval 2 seconds, timeout 1 second.

Normal uses `/home/tanhv/suricata-ai-showcase/current/scripts/demo/vm1-start-normal-service.sh 18080`,
22 `/health` requests to `18080`, and exactly two closed controls `18100,18101`.
The Normal generator has no `--seed`. Stop it only with the reviewed PID-safe
stop script after the three Normal sessions.

After G3 trust is verified, transfer one verified bundle at a time with the
existing `backend.pcap_handoff send --execute` path to the owner-verified VM3
inbox. The transfer uses staged files and publishes the ready marker last; it
never renames or overwrites the original VM1 files. VM3 consumes the flat
files from that same verified inbox and passes the same inbox as `--input-root`
and the same private artifact root as `--private-root`.

The authorized transfer command is:

```bash
VM3_INBOX="$VM3_PRIVATE_ROOT/incoming-pcaps"
PYTHONPATH=/home/tanhv/suricata-ai-tools /home/tanhv/suricata-ai-venv/bin/python \
  -m backend.pcap_handoff send \
  --outbox /home/tanhv/suricata-ai-outbox --run-id "$capture_id" \
  --remote-user tanhv --remote-host 192.168.10.30 \
  --remote-inbox "$VM3_INBOX" --execute
```

The VM3 preflight must prove `VM3_INBOX` is inside the same verified private
root used by the worker and is mode `0700`; otherwise this transfer is not
authorized.

G4 stops on any duplicate hash, missing tuple, count mismatch, drop,
truncation, missing frozen artifact, provenance mismatch, or non-review-only
output. No candidate rule is activated.

## G6: bounded review-only EVE path

G6 remains distinct from G4 and uses only the existing four-feature showcase
artifact at:

```text
/home/tanhv/suricata-ai-showcase/models/showcase_demo
```

The sender timer remains stopped. A genuinely new EVE event may reach VM3 only
through an explicitly authorized bounded lab path whose source, destination,
file, and timestamps are recorded before starting the existing
`vm3-start-worker.sh`. The timer is not restarted and production routing is
not modified. The worker is observed for at most 120 seconds with its existing
64-record/1 MiB cycle limits, then stopped with the PID-safe stop script.

The executable review-only path is:

```bash
/home/tanhv/suricata-ai-showcase/current/scripts/demo/vm3-status.sh
VM3_EVE=/home/tanhv/suricata-ai-showcase/eve-shadow/eve-shadow.jsonl
/home/tanhv/suricata-ai-showcase/current/scripts/demo/vm3-start-worker.sh \
  /home/tanhv/suricata-ai-showcase/models/showcase_demo \
  "$VM3_EVE" showcase_demo
worker_pid="$(cat /home/tanhv/suricata-ai-showcase/runtime/worker.pid)"
tr '\0' ' ' < "/proc/$worker_pid/cmdline"
timeout 120 tail -f /home/tanhv/suricata-ai-showcase/inference/inference.jsonl
/home/tanhv/suricata-ai-showcase/current/scripts/demo/vm3-stop-worker.sh
```

With the sender timer stopped, the only permitted input handoff is an owner-
verified, newly observed EVE line exported from the already-running lab
Suricata source on VM1, copied once to a private VM3 staging file, hash-checked,
and appended once to `VM3_EVE`. The source EVE path must be read-only derived
from the active lab configuration; if it cannot be independently identified,
G6 stops. No synthetic EVE line, timer restart, production-route edit, or
unbounded tail is permitted.

Acceptance requires the same new event/run ID to be observed in the EVE shadow,
inference JSONL, Elasticsearch, and the Kibana-visible index. Latency is the
measured difference between recorded event timestamps, never command duration.
No new correlated event means G6 fails closed.

## G5 exclusion and stop rules

G5 is excluded until G4 supplies an accepted candidate with its actual SID and
rule SHA256. No G5 approval is implied here.

Any integrity mismatch, missing source, unsafe symlink, unexpected process,
storage failure, timer state change, failed trust check, missing evidence, or
operation outside this matrix stops the session. There are no automatic
retries.
