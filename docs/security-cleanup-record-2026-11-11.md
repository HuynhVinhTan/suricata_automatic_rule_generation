# Security cleanup record

Date: 2026-11-11

## Final observed state

- VM1 `/usr/bin/tcpdump`: `cap_net_raw=ep`, root-owned, mode `755`.
- No `tcpdump` process remains.
- Temporary HTTP port `18081` is closed.
- VM1 Suricata and Filebeat are active.
- No capability, sudoers, firewall, production Suricata, Filebeat or EVE-to-ELK
  change was made by this audit.

## Diagnosis boundary

The read-only SSH shell had no permitted/effective capabilities, while PID 1
had the full capability set; `NoNewPrivs=0`, `Seccomp=0`, ext4 was read-write,
and the binaries were not immutable. `setcap` had no file capability. AppArmor
was loaded but its profiles were not readable by the unprivileged audit. The
owner's `sudo -i` failure therefore remains context-specific and unproven.

## Required owner action

In the same interactive root shell that failed, inspect `/proc/$$/status`,
`capsh --print`, and kernel audit messages for `CAP_SETFCAP`/AppArmor/landlock
denials. Then, if authorized by the owner, run `setcap -r /usr/bin/tcpdump` and
verify `getcap -v /usr/bin/tcpdump` shows no capability. This record remains
FAILED until that verification exists.
