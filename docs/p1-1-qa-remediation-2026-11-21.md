# P1.1 QA remediation (2026-11-21)

This remediation remains repository-only. No SSH, deployment, sudo, tcpdump,
traffic generation, production service change, EVE access, or raw PCAP transfer
was performed.

## Runtime-safety changes

- Owner authentication is foreground `sudo -v` and requires an explicit PTY.
- The capture is launched only after authentication, under a `setsid` process
  group; timeout, interruption, readiness failure, and generator failure reap
  the supervisor and terminate the process group.
- The partial PCAP is passed to strict offline verification before atomic rename
  and before `ATTACK_CAPTURE_READY` is printed.
- Packet and EVE verdicts are separate. Any packet validation failure remains
  `BLOCKED`, even when EVE is `PARTIAL`.
- PCAP parsing rejects truncated IPv4 payloads, unexpected five-tuples, and
  packet/timestamp spans beyond the 5,000-packet/120-second capture bounds.
- Manifest attempts now require valid scoped ports/IPs, unique identities,
  in-window timestamps, TCP protocol, and `rst_refused` results.
- EVE reporting counts tuple, flow-id, and event-hash evidence without treating
  one flow event as proof of complete packet coverage.
- Mocked process-level tests cover foreground authentication, PTY guidance,
  readiness, timeout, descendant cleanup, generator failure, validation failure,
  and overwrite refusal.

The SQLite 1 GiB free-space guard was not changed.
