# G4 bidirectional capture preparation — 2026-11-24

`G4_BIDIRECTIONAL_CAPTURE_PREPARED`

This remains offline preparation only. No SSH, sudo, service start, capture,
generator traffic, handoff, inference, G5 or G6 operation was performed. The
failed capture `capture-20261123T230727Z-cdcabc796cfa49f0` and all G3/G4
evidence remain untouched.

## Audited capture path

The reviewed path is VM1 systemd oneshot → `backend.pcap_capture` →
`backend.pcap_handoff.audit_pcap/bundle` → native manifest/ready marker →
`verified_bundle/consume` → pipeline/RST evidence → fail-closed Hybrid review.

The exact bidirectional filter is:

```text
tcp and host 192.168.10.20 and host 192.168.10.10 and (port 18080 or portrange 18100-18123)
```

It preserves `ens33`, snaplen `262144`, the 60-second limit, 64 MiB PCAP cap,
Normal HTTP `18080`, and Attack ports `18100–18123`. It admits both TCP
directions, including SYN/ACK and RST responses, while restricting traffic to
the VM1/VM2 endpoints and approved ports.

Successful native sealing records tcpdump's locale-pinned stderr statistics:
`packets captured`, `packets received by filter`, and `packets dropped by
kernel`. A structurally audited full-snaplen PCAP yields
`packet_records_complete=true` and `snaplen_truncated=false`. Missing drop
statistics remain `capture_drops=null`; malformed/truncated PCAPs are not
sealed. Any drop, count conflict, truncation or unknown integrity value fails
fresh G4 acceptance. Historical manifests without these optional fields remain
readable for preservation but cannot qualify as fresh G4 evidence.

## Version pins and hashes

| Host | Pin | Path/artifact |
|---|---|---|
| VM1 | `08174bf8a9af83c588b48f1c95f7647c22db5118` | `/home/tanhv/suricata-ai-showcase/releases/08174bf8a9af83c588b48f1c95f7647c22db5118` |
| VM1 archive | `8cc7905d4632c0cbcfdad474f2cc61a2e138c8f46e14771594eb245a18a32005` | exact Git archive SHA256 |
| VM2 | `a8fe3e82e701beafc9e47fb7bc5b45064029f8be` | reviewed generator release |
| VM3 | `04438fd864c4312cb22eaf1ce2560e5bcf86861e` | deployed worker release |

The existing VM1 unit remains unchanged. Its known working directory
`/home/tanhv/suricata-ai-tools` does not select the new versioned release.
Release copying therefore does not authorize capture; the unit must first be
retargeted under a separate approval after the read-only inspection passes.

## Owner-controlled deployment

The corrected Windows PowerShell 5.1 deployment interface is
[`g4_prepare_vm1_release.ps1`](../scripts/g4_prepare_vm1_release.ps1):

```powershell
& 'D:\suricata-ai-project-worktrees\feat-complete-suricata-ai-e2e\scripts\g4_prepare_vm1_release.ps1'
```

That is plan-only. The owner must explicitly invoke `-Execute` after approving
the release copy. It:

1. requires branch `feat/complete-suricata-ai-e2e`, a HEAD descending from the
   verified state `624858968e0528c58d6e4284394d0932cf8bd7cb`, and proves the
   pinned release commit is an ancestor;
2. archives the pinned ancestor, not HEAD, and checks archive SHA256;
3. performs a read-only VM1 preflight for root/release collision, unit hash,
   inactive/dead capture service, and absence of tcpdump;
4. creates a unique same-filesystem staging directory under
   `/home/tanhv/suricata-ai-showcase/.runtime-staging/` and transfers the
   archive unchanged;
5. rejects archive traversal, partial extraction, symlinked required files and
   Python SHA256 mismatches;
6. atomically renames the verified extracted directory into the new versioned
   release; and
7. proves the pre-existing `current` pointer, unit SHA256 and service state
   are unchanged before printing `VM1_RELEASE_PASS=TRUE`.

On failure, the new staging directory is reported and no existing release,
pointer, unit, capture, outbox or historical evidence is modified. The script
never edits or reloads systemd and never starts capture.

Prepared release script SHA256:
`e7b800d02a96002959e7aef060d9556d1a150fca8764dae79bed132199a32ff`.

## Separate read-only VM1 inspection

Run the following only as a read-only audit using
[`g4_inspect_vm1_capture.ps1`](../scripts/g4_inspect_vm1_capture.ps1):

```powershell
& 'D:\suricata-ai-project-worktrees\feat-complete-suricata-ai-e2e\scripts\g4_inspect_vm1_capture.ps1'
```

It reports `systemctl cat`, effective `ExecStart`, pre/post hooks, working
directory, identity/capability/sandbox properties, unit/drop-in paths, unit
SHA256, capture service state, resolved source module path and SHA256, current
pointer, and the current pointer's rollback target. It fails on a symlinked
unit, unit hash mismatch, unsafe `current`, or unresolved source module. It
does not call `sudo`, `systemctl start`, `reload`, `enable`, `disable`, or any
write operation.

Prepared inspection script SHA256:
`a237c6e544786db8400506d4c14a7ec385700a6aa90039bf361db631999774ec`.

## Safe retarget plan after release verification

Retargeting is a separate owner-approved operation and is not included in the
deployment script:

1. Run the read-only inspection and record the exact unit content/hash,
   effective `ExecStart`, working directory, module path/hash, service state,
   and rollback target.
2. Confirm the new release exists and its required hashes match the pinned
   archive. Confirm `current`, capture root, outbox, timer state and all
   historical evidence are unchanged.
3. Prepare a root-owned, mode-`0644` unit change whose only intended delta is
   the versioned VM1 source path. Do not alter capture limits, interface, BPF,
   sandboxing or production services.
4. Independently review the complete unit and its SHA256, then obtain the
   separate owner authorization for the unit change and `systemctl daemon-reload`.
5. Before any start, verify the service is inactive/dead, no tcpdump exists,
   free space remains above the established threshold, and the old unit bytes
   and rollback target are recorded.
6. If any check differs, stop. Do not switch `current`, start capture, launch
   generators, or infer G4 acceptance.

Fresh G4 authorization additionally requires six disjoint capture/generator
identities, sealed PCAP/manifest/ready hashes, exact five-tuples and timestamps,
verified `true/false/false` integrity metadata, VM3 `consume` verification, and
review-only frozen-worker output. G5 remains deferred until an accepted
candidate supplies its actual SID and rule SHA256.

## Prepared drop-in workflow (owner execution remains blocked)

The separate [`g4_retarget_vm1_capture_dropin.ps1`](../scripts/g4_retarget_vm1_capture_dropin.ps1)
has SHA256
`515600b647bc9ed9a964f5fcdda1058a6464eacb35fc49e621afdf8310e0df33`.
It is plan-only unless the owner supplies `-Install -Execute` or
`-Rollback -Execute`. Each action uses one owner-visible `ssh -tt` session,
performs `sudo -v` followed by narrowly scoped `sudo -n` file operations and
`daemon-reload`, and never asks Codex to handle a password. Release module
hashing and Python provenance imports run as `tanhv`, never as root.
Installation refuses an existing drop-in, verifies the exact root-owned
mode-0644 drop-in contents, imports from the exact release with bytecode
disabled, and asserts `ens33`, the bidirectional BPF, 60-second duration,
262144 snaplen, 64 MiB cap, inactive capture/send states, and unchanged
security properties. If a post-install check fails, the script removes only
the drop-in and directory created by that invocation, reloads systemd, and
prints an explicit rollback pass/fail marker. Rollback validates and removes
only that exact drop-in without depending on the new release being available,
preserves unrelated drop-ins, reloads systemd, and proves the original
working directory and all recorded properties are restored.

The owner-controlled Windows PowerShell 5.1 controller is
[`g4_vm1_owner_controller.ps1`](../scripts/g4_vm1_owner_controller.ps1). It
requires the independently reviewed exact CI-passed commit SHA externally;
the controller does not hardcode a moving approved HEAD. Example invocation:

```powershell
& 'D:\suricata-ai-project-worktrees\feat-complete-suricata-ai-e2e\scripts\g4_vm1_owner_controller.ps1' `
  -ApprovedHead '<40-character independently reviewed CI-passed commit SHA>'
```

It passes `-RepositoryRoot` to the release-preparation script, uses separate
explicit approval prompts for release publication and drop-in installation,
normalizes CRLF marker output, and emits `VM1_READY_FOR_G4=TRUE` only after
the required post-install inspection and all readiness markers pass.
With a verified published release, add `-ResumeRetargetOnly` to skip release
publication and verify the existing release hashes before requesting the
separate retarget approval.

## Offline CI diagnosis

CI run `45310184394` failed because the synthetic attack fixture was created
before foreground authentication and mocked supervisor startup, so its
one-second packet window could race the strict metadata ordering checks. A
30-second creation-time slack alone is invalid because it puts the generator
window after the real mocked capture. The test now rebases only intact
synthetic PCAP/manifest inputs immediately before each mocked launch, while
leaving intentionally malformed inputs untouched. Strict PCAP, manifest,
timestamp, tuple, RST, drop and integrity checks remain unchanged.
