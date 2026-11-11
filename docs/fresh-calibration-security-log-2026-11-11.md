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

## 2026-11-11T16:02:25Z–16:18:33Z — authorized calibration and holdouts

- Preflight discrepancy: despite the earlier owner statement that capability
  had been revoked, read-only VM1 verification still reported
  `/usr/bin/tcpdump cap_net_raw=ep`. No capability or sudoers change was made.
- `normal-cal-services-02` final accepted attempt: 240 packets, 240/240
  complete records, snaplen 262144, zero kernel drops, 24/24 HTTP 200; PCAP
  SHA256 `1195656c8c53bf01f07bb7d6277210ba0fef4b7cfa6dca394f11f13ce4f0ce54`,
  manifest SHA256 `4e1791c5c55f14c718b10aae968ffa9756e746079470e4563adceb67d3530962`.
  Three earlier synchronization attempts were preserved and rejected because
  each captured only 23 of 24 initial SYNs.
- Frozen calibration thresholds were derived only from the three accepted
  Normal runs before holdout inspection: ports `4`, RST/window `3`, handshake
  failures `2`. Decision SHA256:
  `c7dffd3021d0c0195789e45c369f30108186753076b95586a2d80c9c744b579a`.
- Six independent holdouts passed capture integrity. Attack PCAP SHA256 values:
  `7eb27fe774c8d889480662eaaea1e68b2336cc04c943ff06be399a24e4c0bbb5`,
  `80b118068f89f0939d9a3c9ba72c977b08f95eff74a04e65b31cd548e0258f61`,
  `837dd0b52f3472ce620baf9479f7f44da7515901455f54e2fe907277648a3343`.
  Normal PCAP SHA256 values:
  `a4500b006908c26ffeed932244148c7372f2be2cb8abeb954cfe17ad3cda0fe7`,
  `aad42d5710eb1006b76b744983744f47322137b2703126537b46787e34b01aaf`,
  `5a61ae059d8f25a2aa6bf1672f82d66c36f3e64de8d9d01dde6afca5081a2468`.
- Standalone IF/AE flagged all five windows in all six sessions. Hybrid
  classification was `reconnaissance_consistent` for all Attack holdouts and
  `anomalous_not_reconnaissance` for all Normal holdouts. Review flags remained
  `approved=false`, `deployable=false`, `deployed=false`.
- No executable Suricata rule was approved, loaded, replayed or deployed.
- The temporary HTTP service was stopped and port 18081 verified closed.
- No tcpdump process remains. Capability removal remains owner-controlled.
