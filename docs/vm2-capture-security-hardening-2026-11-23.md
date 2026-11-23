# VM2 capture privileged-boundary hardening (2026-11-23)

## Current verdict

`G2_OFFLINE_SECURITY_REVIEW_READY`

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

## Offline design and security boundary

The replacement `scripts/demo/vm2-capture-supervisor.py` is intended to be
installed as the fixed entrypoint:

`/usr/local/libexec/suricata-ai-showcase/vm2-capture-supervisor`

The installation directory and file must be `root:root`, executable, and not
group- or world-writable. The wrapper has a literal path to this entrypoint;
the release tree is no longer a privileged execution path.

The helper now validates this origin on every capture invocation, without an
`euid` or source-location conditional: `__file__` must equal the exact fixed
installation path, and the file plus every ancestor through `/` must have the
approved root ownership and non-writable modes. The installed shebang is
`#!/usr/bin/python3 -I`, so Python isolated mode ignores `PYTHONPATH`,
`PYTHONHOME`, user site directories, and similar startup injection points.
An alternate copy or unsafe installation fails closed before tcpdump starts.

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
- temporarily creates the capture inode as mode `0644` because Kali's
  tcpdump privilege-dropping behavior must be checked before assuming that a
  dropped tcpdump process can open `/proc/self/fd/<fd>`; after tcpdump exits,
  the helper changes ownership to the fixed evidence-directory owner and
  changes the completed file to mode `0600`. This preserves the unprivileged
  verifier's read access when G2A confirms that the evidence directory is
  owned by `kali`, while preventing other users from reading PCAP contents;
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
Cmnd_Alias SURICATA_VM2_CAPTURE = /usr/local/libexec/suricata-ai-showcase/vm2-capture-supervisor ^--output /home/kali/suricata-ai-showcase/evidence/attack-[0-9]{8}T[0-9]{6}Z\.pcap\.partial\.pcap --stop-file /home/kali/suricata-ai-showcase/evidence/attack-[0-9]{8}T[0-9]{6}Z\.pcap\.stop$
kali ALL=(root) SURICATA_VM2_CAPTURE
```

The exact syntax must be accepted by the VM2 sudo version under `visudo -cf`.
Argument regular expressions are supported by sudoers starting with sudo
1.9.10 and use POSIX extended regular expressions; G2A must still record
`sudo -V` and validate this exact file on VM2 rather than assuming support from
the CI image. The owner must not replace the anchored expression with `*`,
`ALL`, a shell, or a generic command rule. The helper's root-owned fixed path
constrains this capture workflow only; it is not a system-wide least-privilege
policy. A narrow sudoers rule cannot revoke an existing broader grant (for
example `kali` being in the `sudo` group). Any broader grant requires a
separate owner decision; this task does not remove groups, edit global sudo
privileges, or add `NOPASSWD`.

## G2A — read-only VM2 inspection authorization

Authorize only the following inspection, with no installation, sudo command
execution as root, tcpdump, generator, traffic, release activation, or
sudoers change. The owner should preserve the output as evidence:

```sh
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
hostname
id -un
id kali
sudo -l -U kali
sudo -V
visudo -c
namei -l /usr/local/libexec/suricata-ai-showcase/vm2-capture-supervisor
stat -c '%n %F %U:%G %a %u:%g' \
  /usr/local/libexec \
  /usr/local/libexec/suricata-ai-showcase \
  /usr/local/libexec/suricata-ai-showcase/vm2-capture-supervisor \
  /home/kali/suricata-ai-showcase \
  /home/kali/suricata-ai-showcase/current \
  /home/kali/suricata-ai-showcase/evidence
sha256sum /usr/local/libexec/suricata-ai-showcase/vm2-capture-supervisor
command -v tcpdump python3 sha256sum namei visudo
tcpdump --version
python3 --version
findmnt -T /usr/local/libexec/suricata-ai-showcase/vm2-capture-supervisor
```

G2A passes only if the fixed helper and all ancestors are root-owned and not
group/world-writable, the evidence directory is a stable non-symlink directory
  owned by `kali` and mode `0700`, `sudo -l -U kali` exposes no unacceptable
broader grant, the installed sudo version accepts the anchored argument regex,
and the required binaries/filesystem are the reviewed ones. Do not infer
tcpdump `/proc/self/fd` compatibility from the fake-tcpdump tests; that is a
separate live compatibility check requiring owner authorization.

## G2B — installation authorization

Authorize this separately and only after G2A passes. The exact reviewed
commit and hashes must be filled from the final pushed commit before approval:

```text
REVIEWED_COMMIT=fe70982
SOURCE_ARCHIVE_SHA256=7375474676534fe4a2caf723e4898b38d08f29101f4a1b6f0f6272fa741a6c5c
HELPER_SHA256=b59bbc94b6e949e8f1be3415dfcd175312297a956309db9f9b6151f17231551e
```

The owner-approved installation sequence is:

```sh
set -eu
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
STAGED=/home/kali/suricata-ai-showcase/install-staging/vm2-capture-supervisor
DEST=/usr/local/libexec/suricata-ai-showcase/vm2-capture-supervisor
printf '%s  %s\n' "$HELPER_SHA256" "$STAGED" | sha256sum -c -
sudo -v
sudo install -d -o root -g root -m 0755 /usr/local/libexec/suricata-ai-showcase
sudo install -o root -g root -m 0755 "$STAGED" "$DEST"
printf '%s  %s\n' "$HELPER_SHA256" "$DEST" | sha256sum -c -
sudo namei -l "$DEST"
sudo stat -c '%n %F %U:%G %a %u:%g' "$DEST"
```

The proposed `/etc/sudoers.d/suricata-ai-showcase-vm2-capture` contents are
exactly:

```sudoers
Cmnd_Alias SURICATA_VM2_CAPTURE = /usr/local/libexec/suricata-ai-showcase/vm2-capture-supervisor ^--output /home/kali/suricata-ai-showcase/evidence/attack-[0-9]{8}T[0-9]{6}Z\.pcap\.partial\.pcap --stop-file /home/kali/suricata-ai-showcase/evidence/attack-[0-9]{8}T[0-9]{6}Z\.pcap\.stop$
kali ALL=(root) SURICATA_VM2_CAPTURE
```

Install it as `root:root` mode `0440` only after recording the pre-change
policy, then validate with `sudo visudo -cf /etc/sudoers.d/suricata-ai-showcase-vm2-capture`
and re-run `sudo -l -U kali`.
Do not activate the wrapper release until the fixed helper, exact hash,
sudoers parse, effective policy and ownership/mode checks all pass. The
wrapper's existing user-owned release activation is a separate non-root step;
it must point to the reviewed release and must not modify production services.

Rollback, only with owner approval, is limited to recording the installed
hashes, removing this new drop-in and fixed helper, re-validating the remaining
sudo policy with `visudo -c` and `sudo -l -U kali`, and restoring the prior
reviewed user-owned wrapper release. It must not remove `kali` from groups or
change unrelated sudoers, Suricata, Filebeat, or ELK state.

## Installation and rollback plan — owner approval required

The following is a plan, not an executed command:

1. Complete G2A and record its read-only evidence.
2. Transfer the reviewed source release and verify its archive SHA256 and the
   entrypoint SHA256 before installation.
3. Complete G2B only after a separate owner approval.

## Required approval after installation

The prior one-run capture approval remains unconsumed, but it covered the old
privileged mechanism. A separate owner reconfirmation is required for the
revised root-owned fixed-helper invocation. Only after G2A, G2B, post-install
verification, the separately reconfirmed one-run authorization, and a fresh
read-only capture preflight may one bounded VM2 capture proceed. No live
tcpdump compatibility check or capture is part of this offline review.
