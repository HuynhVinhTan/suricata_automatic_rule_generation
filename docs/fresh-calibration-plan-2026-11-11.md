# Fresh hybrid calibration and holdout plan

Status: **pre-registered; capture authorization required**

This plan preserves the frozen IF/AE model, five-feature contract, review-only
safety, and production Suricata/EVE-to-ELK path. No capture or traffic
generation has started under these run IDs.

## Fixed scope

- VM1 capture: `suricata-vm1`, interface `ens33`
- VM2 generator: `suricata-vm2`, interface `eth1`
- Source allowlist: `192.168.10.20`
- Destination allowlist: `192.168.10.10`
- Closed-port allowlist: `18100-18123`
- Synthetic HTTP port: `18080`, plus only explicitly verified additional ports
- Capture filter: `tcp and host 192.168.10.20 and host 192.168.10.10`
- Capture mode: classic Ethernet PCAP, `tcpdump -p -s 0`
- Maximum duration per run: 120 seconds, including bounded setup/cleanup
- Private raw output root: `data/private/fresh-calibration-20261111/<run-id>/`
- VM1 working root: `/home/tanhv/suricata-rule-review/fresh-calibration-20261111/<run-id>/`

## Normal calibration runs

| Run ID | Scenario | Pre-registered ground truth |
|---|---|---|
| `normal-cal-http-01` | Legitimate HTTP access | Only approved HTTP requests to verified `18080`; expected successful responses |
| `normal-cal-services-02` | Benign multi-service checks | Approved requests across explicitly verified synthetic service ports; no external destinations |
| `normal-cal-rst-03` | Challenging benign monitoring | Approved closed-port checks in `18100-18123`, expected legitimate RST/failed connections, with generator results recorded |

Each run must have an independent generator result and an immutable capture
manifest. A scenario label is not inferred from a filename or PCAP behavior.

## Independent holdouts

| Attack | Normal |
|---|---|
| `attack-holdout-01` | `normal-holdout-01` |
| `attack-holdout-02` | `normal-holdout-02` |
| `attack-holdout-03` | `normal-holdout-03` |

Holdout traffic is not to be generated or inspected for threshold selection.
Thresholds are frozen from accepted Normal calibration runs before any holdout
evaluation.

## Required evidence per run

The capture-time manifest/log must bind the run ID, scenario label, source and
destination allowlists, interface, UTC start/end, exact generator command and
seed, exact tcpdump command/options, clean shutdown, original tcpdump statistics,
zero kernel drops, global-header snaplen, per-record captured/original lengths,
PCAP SHA256, and hashes of the original manifest/log files. Missing or
contradictory fields reject the run.

The owner-controlled temporary tcpdump capture permission may be used only if
explicitly authorized for these exact runs. After all captures, the owner must
revoke it with `sudo setcap -r /usr/bin/tcpdump` and verify `getcap
/usr/bin/tcpdump` returns no capability. No sudoers, firewall, production
Suricata, EVE, model, or benchmark changes are part of this plan.

## Frozen evaluation outputs

For accepted calibration only, record the 60-second sliding-window maxima for
distinct destination ports and correlated RSTs, handshake/payload statistics,
the exact calibration manifest SHA256, the accepted PCAP SHA256 values, and the
derived frozen thresholds. Then report standalone IF/AE results and hybrid
Attack/Normal results with exact sample counts. Rule feasibility is evaluated
only after independent hybrid validation and remains review-only.
