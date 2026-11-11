# Fresh calibration security log

## 2026-11-11T15:23:59.8343887Z — pre-capture authorization

- Owner authorization: temporary use of the existing VM1 tcpdump capability for `normal-cal-http-01`, `normal-cal-services-02`, and `normal-cal-rst-03` only.
- VM1: `suricata-vm1`, `ens33`, `192.168.10.10`.
- VM2: `suricata-vm2`, `eth1`, `192.168.10.20`.
- Authorized destination ports: `18080` and `18100–18123` only.
- Current read-only capability state: `/usr/bin/tcpdump cap_net_raw=ep`, owner `root:root`, mode `755`.
- Discrepancy: this current state conflicts with the earlier owner observation reporting no file capability; owner confirmed the discrepancy is unexplained and explicitly authorized temporary use without authorizing any privilege modification.
- No `setcap`, `sudoers`, firewall, production Suricata, Filebeat, or EVE-to-ELK change was performed.
- Capture-dependent work remains bounded to the authorized runs; capability removal remains owner-controlled after completion.

## 2026-11-11T15:28:39.720384074Z — Phase 3 result

- `normal-cal-http-01`: completed; 228 packets, snaplen 262144, 228/228 captured=original record lengths, 0 trailing bytes, 0 kernel drops; PCAP SHA256 `2d1fb8b3ab6668bdfa03832a0418508ee6fff43a2e9e27081a3b0f9248d9730b`.
- `normal-cal-rst-03`: completed; 232 packets, snaplen 262144, 232/232 captured=original record lengths, 0 trailing bytes, 0 kernel drops; PCAP SHA256 `41865c066fed08313bc4478fc91894543ed2d2065bdf6be8ac4e07683355b7ee`.
- `normal-cal-services-02`: BLOCKED; no additional authorized synthetic services were listening, and no service or port was started.
- No holdout traffic, rule generation, model change, production reload, firewall change, or capability change occurred.
- Threshold status: NOT FROZEN; the two completed runs provide only one HTTP service plus two closed controls and are insufficient for the planned challenging multi-service calibration.
