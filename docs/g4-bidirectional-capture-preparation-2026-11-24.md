# G4 bidirectional capture preparation — 2026-11-24

`G4_BIDIRECTIONAL_CAPTURE_PREPARED`

This is offline preparation only. No SSH, sudo, service start, timer change,
capture, generator traffic, PCAP handoff, worker execution, G5 operation or
G6 change was performed. The failed capture
`capture-20261123T230727Z-cdcabc796cfa49f0` and all existing G3/G4 evidence are
not read-modified-written by this change.

## Audited data path

The audited path is:

```text
VM1 systemd oneshot
  -> backend/pcap_capture.py
  -> backend/pcap_handoff.audit_pcap/bundle
  -> native manifest + ready marker
  -> backend/pcap_handoff verified_bundle/consume
  -> src/netids/pipeline.py capture metadata
  -> src/netids/rst_evidence.py capture_integrity
  -> src/netids/hybrid_review.py
```

The previous VM1 filter was one-way and excluded the requested service-port
allowlist. The prepared filter is exactly:

```text
tcp and host 192.168.10.20 and host 192.168.10.10 and (port 18080 or portrange 18100-18123)
```

It preserves Normal HTTP port `18080`, Attack ports `18100–18123`, VM1
`ens33`, snaplen `262144`, the 60-second limit and the 64 MiB PCAP limit. The
`host` terms admit both TCP directions; the port expression applies to either
source or destination port, so SYN/SYN-ACK/ACK, payload and RST responses are
eligible without admitting unrelated lab traffic.

## Integrity contract

`backend.pcap_capture` now captures tcpdump's locale-pinned stderr summary:

```text
N packets captured
N packets received by filter
N packets dropped by kernel
```

The native manifest records:

```json
{
  "interface": "ens33",
  "bpf_filter": "tcp and host 192.168.10.20 and host 192.168.10.10 and (port 18080 or portrange 18100-18123)",
  "packet_records_complete": true,
  "snaplen_truncated": false,
  "capture_drops": false,
  "tcpdump_statistics": {
    "packets_captured": 0,
    "packets_received_by_filter": 0,
    "packets_dropped_by_kernel": 0,
    "status": "verified"
  }
}
```

The counts above are a schema example, not runtime evidence. The actual
values come from tcpdump and the PCAP audit. If a tcpdump statistic is absent,
the corresponding evidence remains unverified and `capture_drops` is `null`.
An audited full-snaplen PCAP is marked `packet_records_complete=true` and
`snaplen_truncated=false`; malformed or truncated records are not sealed.
Any kernel drop, truncation, count conflict or incomplete integrity metadata
prevents a fresh G4 bundle from being accepted. The runtime contract requires
`true/false/false` and the exact interface/filter before G4 evidence can be
correlated. Hybrid review remains fail-closed as
`ambiguous_incomplete_capture` whenever completeness is not proven.

Historical manifests without these optional fields remain verifiable for
preservation and audit; they do not qualify as fresh G4 acceptance evidence.

## Versioned release pins

The capture and controller preparation is pinned to these independently
identified releases:

| Host | Release | Path or artifact |
|---|---|---|
| VM1 `192.168.10.10` | commit `08174bf8a9af83c588b48f1c95f7647c22db5118` | `/home/tanhv/suricata-ai-showcase/releases/08174bf8a9af83c588b48f1c95f7647c22db5118` |
| VM1 archive | SHA256 `8cc7905d4632c0cbcfdad474f2cc61a2e138c8f46e14771594eb245a18a32005` | exact LF Git archive of the VM1 release commit |
| VM2 `192.168.10.20` | reviewed release `a8fe3e82e701beafc9e47fb7bc5b45064029f8be` | `/home/kali/suricata-ai-showcase/releases/a8fe3e82e701beafc9e47fb7bc5b45064029f8be/scripts/lab_slow_port_scan.py` |
| VM3 `192.168.10.30` | deployed commit `04438fd864c4312cb22eaf1ce2560e5bcf86861e` | `/home/tanhv/suricata-ai-showcase/releases/04438fd864c4312cb22eaf1ce2560e5bcf86861e` |

The VM2 generator file hash must be read and compared with the already
approved VM2 release evidence before any future session. It is deliberately
not invented here. The VM3 release is the user-confirmed `VM3_DEPLOY_PASS`
release and remains unchanged.

The existing VM1 unit was not changed. Its previously observed
`WorkingDirectory=/home/tanhv/suricata-ai-tools` does not select the new
versioned release. Therefore extracting the release alone is insufficient:
the owner must separately reconcile the unit's effective working directory or
approved versioned wrapper, verify the unit SHA/policy, and only then use the
controller. This preparation does not authorize or perform that service
change.

## Owner-executable VM1 deployment preparation

Run only after the separate runtime authorization covers the release copy. The
block transfers the exact archive bytes, refuses an existing release, verifies
the archive and source hashes, and leaves `current` and the systemd unit
unchanged. It does not start the service.

```powershell
$ErrorActionPreference = 'Stop'
$Repo = 'D:\suricata-ai-project-worktrees\feat-complete-suricata-ai-e2e'
$Commit = '08174bf8a9af83c588b48f1c95f7647c22db5118'
$ArchiveSha256 = '8cc7905d4632c0cbcfdad474f2cc61a2e138c8f46e14771594eb245a18a32005'
$Vm1 = 'tanhv@192.168.10.10'
$Root = '/home/tanhv/suricata-ai-showcase'
$Release = "$Root/releases/$Commit"
$Archive = Join-Path ([IO.Path]::GetTempPath()) "suricata-ai-vm1-$Commit.tar"

Set-Location $Repo
if ((git rev-parse HEAD).Trim() -ne $Commit) { throw 'Controller source is not the pinned VM1 commit.' }
git archive --format=tar --output=$Archive $Commit
if ($LASTEXITCODE -ne 0) { throw 'git archive failed.' }
try {
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Archive).Hash.ToLowerInvariant()
    if ($actual -ne $ArchiveSha256) { throw "VM1 archive SHA256 mismatch: $actual" }
    & ssh -o BatchMode=yes -o StrictHostKeyChecking=yes $Vm1 "set -eu; test ! -e '$Release'; test -d '$Root/releases'; test -d '$Root'"
    if ($LASTEXITCODE -ne 0) { throw 'VM1 release preflight failed.' }
    & scp -B -o BatchMode=yes -o StrictHostKeyChecking=yes $Archive "$Vm1`:/tmp/suricata-ai-vm1-$Commit.tar"
    if ($LASTEXITCODE -ne 0) { throw 'VM1 archive transfer failed.' }
    $payload = @'
set -eu
ROOT=/home/tanhv/suricata-ai-showcase
COMMIT=08174bf8a9af83c588b48f1c95f7647c22db5118
ARCHIVE=/tmp/suricata-ai-vm1-08174bf8a9af83c588b48f1c95f7647c22db5118.tar
EXPECTED=8cc7905d4632c0cbcfdad474f2cc61a2e138c8f46e14771594eb245a18a32005
RELEASE="$ROOT/releases/$COMMIT"
test ! -e "$RELEASE"
test "$(sha256sum "$ARCHIVE" | awk '{print $1}')" = "$EXPECTED"
mkdir "$RELEASE"
tar -xf "$ARCHIVE" -C "$RELEASE"
test "$(sha256sum "$RELEASE/backend/pcap_capture.py" | awk '{print $1}')" = 1a96c9264ce6c46011149a7adfaad908e06dcbc4cf40b48c2c496cf1933712b3
test "$(sha256sum "$RELEASE/backend/pcap_handoff.py" | awk '{print $1}')" = 0442e59ddd47b11608bd9ad110d512e6db338fc5a89b5cb93671746ccee153de
test ! -e "$ROOT/current" || test "$(readlink -f "$ROOT/current")" != "$RELEASE"
rm -- "$ARCHIVE"
printf '%s\n' VM1_RELEASE_READY=TRUE
'@
    $bytes = [Text.Encoding]::UTF8.GetBytes(($payload -replace "`r`n", "`n"))
    $encoded = [Convert]::ToBase64String($bytes)
    & ssh -o BatchMode=yes -o StrictHostKeyChecking=yes $Vm1 "printf %s '$encoded' | base64 -d | bash"
    if ($LASTEXITCODE -ne 0) { throw 'VM1 release extraction or hash verification failed.' }
}
finally {
    if (Test-Path -LiteralPath $Archive) { Remove-Item -LiteralPath $Archive -Force }
}
```

This block is preparation for the later capture gate. It intentionally does
not switch `current`, rewrite the unit, reload systemd, or start capture.

## Prepared six-session controller contract

The offline controller contract is
`[scripts/runtime_orchestration_contract.py](../scripts/runtime_orchestration_contract.py)`.
`g4_release_paths()` pins the three versioned roots; the validator binds each
fresh native capture ID to its distinct generator ID and requires:

- Attack: 24 distinct destination ports `18100–18123`, interval 2 seconds,
  timeout 1 second, VM2 source `192.168.10.20` to VM1 `192.168.10.10`.
- Normal: 22 `/health` requests to `18080` plus exactly two closed controls
  `18100,18101`, with the reviewed VM1 Normal service start/stop scripts.
- Every session: a fresh capture ID, fresh generator ID and exclusive output
  directory; one VM1 60-second capture; one VM2 generator invocation; no retry.
- Native manifest: exact BPF/interface, packet/SYN counts, timestamp ordering,
  PCAP/manifest/ready hashes, `packet_records_complete=true`,
  `snaplen_truncated=false`, `capture_drops=false`, and verified tcpdump
  statistics.
- VM3: the actual sealed bundle is verified with `backend.pcap_handoff
  consume` and the frozen worker is run from the pinned `04438fd...` release
  with review-only output. `--expected-sha256` alone is not sufficient.

For PowerShell-to-Bash transport, use the base64 technique in the deployment
block: construct the remote script as a single-quoted PowerShell here-string,
normalize CRLF to LF, base64-encode the bytes, and let the remote shell decode
and run it. Do not interpolate `$R`, `$O`, `$capture_id`, or literal `|` in an
unquoted PowerShell here-string. The VM1 readiness script must observe
`ActiveState=activating`, `SubState=start`, and the exact tcpdump command before
the VM2 invocation is launched; any readiness, path, hash, timing, drop,
truncation, tuple, count or worker-integrity failure stops the six-session
sequence without retry.

## Evidence required before six-session authorization

For each of the six sessions, preserve the native capture directory and the
VM2 generator directory. The acceptance record must contain the native
capture ID, generator ID, PCAP SHA256, manifest SHA256, ready-marker SHA256,
generator JSON SHA256, tcpdump statistics, capture drops, packet/SYN counts,
five-tuples, start/end/sealed timestamps, and the worker's review-only
summary. The six sessions must have disjoint run identities and provenance.

No G4 acceptance, candidate approval, SID or rule SHA is asserted by this
offline preparation. G5 remains deferred until a real accepted candidate
supplies its actual SID and rule SHA256.

`G4_BIDIRECTIONAL_CAPTURE_PREPARED`
