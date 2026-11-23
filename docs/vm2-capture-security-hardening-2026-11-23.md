# VM2 capture privileged-boundary hardening (2026-11-23)

## Current verdict

`G2_BLOCKED_PRIVILEGE_BOUNDARY`

This is repository-only preparation. The existing VM2 release is unchanged;
no sudo command, tcpdump process, generator, traffic, sudoers edit, or root
installation was performed.

## Root cause

The old `vm2-capture-supervisor.sh` was user-owned and group-writable inside
the user-owned release tree, while the wrapper executed it through `sudo`. It
also accepted an arbitrary command after `--`, trusted a user-writable PID
file for process-group signaling, and allowed root-side output/status paths to
be selected by the caller. A root-owned copy alone would not fix the path and
argument problems.

## Offline design

The replacement `scripts/demo/vm2-capture-supervisor.py` is intended to be
installed as the fixed entrypoint:

`/usr/local/libexec/suricata-ai-showcase/vm2-capture-supervisor`

The installation directory and file must be `root:root`, executable, and not
group- or world-writable. The wrapper has a literal path to this entrypoint;
the release tree is no longer a privileged execution path.

The privileged entrypoint accepts exactly `--output` and `--stop-file`. It:

- allows only a timestamped direct child of the fixed evidence directory and a
  matching `.stop` basename;
- opens every evidence-directory component with `O_NOFOLLOW`, creates output
  with `O_CREAT|O_EXCL|O_NOFOLLOW`, and checks the inode after capture;
- constructs `/usr/bin/tcpdump` internally with fixed `eth1`, snaplen `96`,
  count `5000`, the two-way VM2/VM1 filter, and ports `18100–18123`;
- creates the tcpdump process group itself and signals only that trusted group;
  no PID file is accepted or read;
- polls a stop marker that it never writes, enforces the 120-second timeout,
  escalates INT/TERM/KILL, and fails closed if the output inode is replaced or
  removed;
- preserves the wrapper’s partial-PCAP, log, metadata, verification, timeout,
  and final publish contract. `ATTACK_CAPTURE_READY` remains downstream of
  strict verification and final rename.

The wrapper still performs the owner-interactive `sudo -v`, then uses
non-interactive sudo only for the fixed helper invocation. No production
fallback capability or unrestricted command is introduced.

## Proposed sudo policy — not installed

The owner must inspect the effective policy first. VM2 previously showed
`kali` in the `sudo` group; a narrow rule does not constrain any broader
existing `sudo`-group grant. The effective result of `sudo -l -U kali` and
`visudo -c` must therefore be recorded before installation.

After that inspection, the intended command specification is a single
root-owned executable with a full anchored argument expression matching only
the two reviewed evidence basenames:

```sudoers
Cmnd_Alias SURICATA_VM2_CAPTURE = /usr/local/libexec/suricata-ai-showcase/vm2-capture-supervisor ^--output /home/kali/suricata-ai-showcase/evidence/attack-[0-9]{8}T[0-9]{6}Z\\.pcap\\.partial\\.pcap --stop-file /home/kali/suricata-ai-showcase/evidence/attack-[0-9]{8}T[0-9]{6}Z\\.pcap\\.stop$
kali ALL=(root) SURICATA_VM2_CAPTURE
```

The exact syntax must be accepted by the VM2 sudo version under `visudo -cf`;
the owner must not replace the anchored expression with `*`, `ALL`, a shell,
or a generic command rule. The existing broad policy, if present, must be
removed or separately constrained by the owner because this rule cannot
override it.

## Installation and rollback plan — owner approval required

The following is a plan, not an executed command:

1. Transfer the reviewed source release and verify its archive SHA256 and the
   entrypoint SHA256 before installation.
2. With owner-interactive sudo, create
   `/usr/local/libexec/suricata-ai-showcase` as `root:root` mode `0755` and
   install the entrypoint as `root:root` mode `0755` (or `0555` if the local
   policy permits it).
3. Run `namei -l`, `stat`, `sha256sum`, `visudo -cf`, and an exact `sudo -l`
   review; do not start capture during these checks.
4. Activate the reviewed user-owned wrapper release only after the fixed
   helper and sudo policy are independently verified.
5. For rollback, remove only the new sudoers drop-in and fixed helper after
   recording their hashes, then restore the prior reviewed wrapper release;
   do not alter production Suricata, Filebeat, or ELK state.

## Required approval after installation

The prior one-run capture approval remains unconsumed, but it covered the old
privileged mechanism. A separate owner reconfirmation is required for the
revised fixed-helper invocation. Only after that reconfirmation and a fresh
read-only preflight may one bounded VM2 capture proceed.
