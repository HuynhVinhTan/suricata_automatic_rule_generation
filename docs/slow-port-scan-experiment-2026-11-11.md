# Slow TCP port-scan versus Normal validation

## Status

This experiment is **BLOCKED before traffic generation** because VM2 is not available through a usable SSH alias. No Attack or Normal label, PCAP, model result, or rule approval was fabricated. The prior SID 9103001 result remains rejected and is not reused.

## Preflight evidence

| Check | Result |
|---|---|
| Local branch/HEAD | `feat/pcap-ai-worker-integration` / `30197eea9702227aed70465b3fd589413ac55afb` |
| VM1 alias | `suricata-vm1`, authenticated non-interactively |
| VM1 capture interface | `ens33`, `192.168.10.10/24` |
| VM3 alias | `suricata-vm3`, authenticated non-interactively |
| VM3 capture interface | `ens33`, `192.168.10.30/24` |
| VM2 alias | Initially unresolved; later verified as Kali `192.168.10.20/24` |
| Production services | Suricata and Filebeat active; no restart/reload performed |

The configured fallback SSH identities for the unresolved VM2 name use the local default username `asus-pro`. That username was not assumed or tried against an IP address. The owner action required is: provide a working SSH config alias for the Kali scanner VM, including its verified private-lab address, username, and existing SSH-agent key mapping. No password automation is required or requested.

VM2 subsequently became reachable and was verified as Kali on `eth1` at `192.168.10.20/24`. VM1 port verification found a temporary HTTP service candidate on `192.168.10.10:18080` and confirmed ports `18100` through `18123` returned `ECONNREFUSED` from VM2. Capture then stopped at VM1 because the authenticated user lacks `CAP_NET_RAW`; `sudo -n tcpdump` requires interactive authentication, while production Suricata `pcap-log` is disabled. The owner action now required is to grant a narrowly scoped non-interactive capture capability for the lab interface, for example a dedicated capture service/account or a reviewed `tcpdump` capability, without changing production Suricata configuration. The temporary HTTP service was stopped without generating traffic.

## Experiment design held for execution

After VM2 access is supplied, the planned experiment is:

1. Discover VM2's actual `192.168.10.0/24` interface and route.
2. Verify two open synthetic service ports on VM1 and at least 24 closed TCP ports that return RST rather than timing out.
3. Run one deterministic slow scan with 24 closed ports, one connection approximately every two seconds, and a randomized-but-recorded order.
4. Run a Normal session with 22 successful HTTP 200 requests to one or two open services plus at most two closed-port negative controls over the same duration.
5. Capture both directions at full snap length on VM1 without changing the production capture service.
6. Correlate SYN, SYN-ACK, ACK, RST/RST-ACK, payload, HTTP, and flow evidence by TCP 4-tuple and timestamp.
7. Keep calibration and holdout sessions separate; freeze the existing IF/AE model and thresholds before holdout evaluation.

No threshold, model bundle, five-feature contract, production YAML, production rule file, or EVE-to-ELK path was changed during preflight.

## Implemented independent evidence layer

`src/netids/rst_evidence.py` correlates server-direction RST and RST-ACK packets with preceding client SYNs, de-duplicates retransmissions, preserves no-response/filtered traffic as unknown evidence, and reports RST ratio, handshake success ratio, bidirectional payload ratio, failed connections, RST windows, and PCAP provenance. It does not add these fields to the frozen model feature vector.

`src/netids/rulegen.py` now supports a separate review-only RST rule family. Its threshold is `max(Normal calibration RST count) + 1`; Normal validation, ML consensus, port diversity, attack RST evidence, SID collision checks, and provenance are required. The rule uses `flags:R` and `threshold:type threshold,track by_dst`, so it does not claim to count unique destination ports. SIDs 9102001, 9102002, 9103001, and 9103002 are reserved from allocation.

## Isolated syntax evidence

The rule template was checked with VM1's isolated Suricata `8.0.3 RELEASE` configuration. The parser returned `Configuration provided was successfully loaded. Exiting.` The isolated test used a separate rule file and log directory. Production Suricata was not reloaded or restarted.

## Required remaining evidence

The following cannot be honestly reported until VM2 access and independent sessions exist:

- Attack and Normal PCAP SHA256 values for this experiment.
- Verified RST/handshake ground truth.
- Frozen IF/AE window and session confusion matrices.
- Baseline versus augmented holdout alert counts.
- False-positive-free RST rule approval.
- Feature, inference, generation, transfer, and reload latency from real session timestamps.
- Multiple independent Attack and Normal holdouts.

## Copy-ready project update

Experiment status: **blocked at VM2 preflight**. VM1 and VM3 are reachable and production protection remains intact. The independent RST evidence implementation and review-only RST rule generator are unit-tested and the RST rule syntax passes isolated Suricata 8.0.3 validation. No Attack/Normal claims are made until the owner supplies a working VM2 SSH alias and the controlled sessions are captured.
