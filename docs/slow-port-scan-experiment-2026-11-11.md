# Slow TCP port-scan versus Normal validation

## Status

This experiment completed controlled Attack and Normal holdouts, but the final rule gate **failed**. No rule was generated, deployed, or replayed. The prior SID 9103001 result remains rejected and is not reused.

## Preflight evidence

| Check | Result |
|---|---|
| Local branch/HEAD | `feat/pcap-ai-worker-integration` / updated by this work |
| VM1 alias | `suricata-vm1`, authenticated non-interactively |
| VM1 capture interface | `ens33`, `192.168.10.10/24` |
| VM3 alias | `suricata-vm3`, authenticated non-interactively |
| VM3 capture interface | `ens33`, `192.168.10.30/24` |
| VM2 alias | `suricata-vm2`, verified as Kali `192.168.10.20/24` |
| Production services | Suricata and Filebeat active; no restart/reload performed |

VM2 was verified on `eth1` at `192.168.10.20/24`. VM1 port verification found the temporary HTTP service on `192.168.10.10:18080` and confirmed ports `18100` through `18123` returned `ECONNREFUSED` from VM2. The owner has verified that `/usr/bin/tcpdump` has no file capability after capture completion; no capability or sudoers change was performed in this continuation.

## Experiment design held for execution

The executed experiment was:

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

## Evidence gate outcome

PCAP hashes, RST/handshake ground truth, frozen IF/AE holdout results, and independent Attack/Normal evidence are recorded below. The false-positive-free rule gate did not pass because the frozen IF and AE models flagged every Normal v03 window. No candidate rule, transfer, reload, or deployment was authorized.

## 2026-11-11 resumed-run evidence

The confirmed SSH aliases were usable. A one-packet proof on VM1 `ens33` used `tcpdump -p -s 0 -c 1` and one VM2 connection attempt to port 18100. It captured one readable client SYN in classic Ethernet PCAP with snaplen 262144, zero kernel drops, and SHA256 `8ad41134fa71555290772b434d244f72b91f1995ec41356b50b79354abf6893a`.

Final independent sessions used a bidirectional filter for the private lab pair (`tcp and host 192.168.10.20 and host 192.168.10.10`), `-p -s 0`, classic Ethernet PCAP, and zero kernel drops:

| Session | Generator ground truth | PCAP packets | SYNs | RSTs | Handshake/payload flows | PCAP SHA256 |
|---|---|---:|---:|---:|---:|---|
| Attack v02 | 24 closed ports, all `ECONNREFUSED` | 48 | 24 | 24 | 0 | `a8858ee8073e63b0d1cf3a666ffad36670b0c36ca3e801414b9df2725da06f17` |
| Normal v03 | 22 HTTP 200 `/health` + 2 closed controls | 226 | 24 | 2 | 22 | `89a8f6bc355b93341df8fd615d551b17efe3fb4c33b19a332e21135eccdaa4e4` |

RST correlation marked both captures complete: Attack `rst_ratio=1.0`, 24/24 RST-ACK responses, 24 unique destination ports; Normal `rst_ratio=0.0833333333`, 2/2 RST-ACK responses, 3 unique destination ports, and 22 bidirectional payload flows. The earlier one-way captures and the first Normal capture that contained only 23 SYNs are retained as non-qualifying evidence and are not used for claims.

Frozen IF/AE inference used model SHA256 `206dadafc8d6cd96e21d838a52211d9b06d4a6ec541ea5c9a9ae8a6724ffbf5d`, with no training or threshold change. Both final sessions produced 5 windows, with IF=5, AE=5, and consensus=5. Because Normal also produced 5/5 consensus alerts, the independent false-positive/ML gate failed. No RST-aware rule was generated, and isolated Suricata 8.0.3 validation/replay was correctly not run for a nonexistent candidate.

## Hybrid review layer

`src/netids/hybrid_review.py` adds a separate review-only decision layer. It does not alter the five-feature contract, model files, or IF/AE thresholds. The worker now carries the validated manifest capture-integrity metadata into this layer. Calibration uses only five explicitly audited, Normal-labeled PCAP references: `normal-train`, `normal-cal`, `normal-independent-20261031-v01`, `normal-matched12-20261031-v01`, and `normal-multiport-20261031-v01`. `tcp-connect-recon-20261031-v01` is excluded: packet behavior is Normal-like, but no explicit ground-truth manifest was found and its name is ambiguous. The accepted references observed a ceiling of 12 distinct ports in a 60-second window, zero correlated server RSTs, and zero incomplete handshakes, producing thresholds of 13 ports, 1 RST, and zero allowed Normal handshake failures. Whole-PCAP distinct-port totals are retained for reporting only; classification uses the 60-second sliding-window maximum.

The final holdouts were evaluated once with those frozen hybrid thresholds:

| Session | ML consensus | Hybrid classification | Result |
|---|---:|---|---|
| Attack v02 | 5/5 | `reconnaissance_consistent` | All calibrated conditions passed |
| Normal v03 | 5/5 | `anomalous_not_reconnaissance` | Port diversity and successful-handshake conditions failed |

The distinction is hybrid protocol evidence, not improved standalone IF/AE accuracy. The layer always returns condition-level explanations and keeps `approved=false`, `deployable=false`, and `deployed=false`. Incomplete capture evidence is classified as ambiguous and cannot pass.

Attack v02 and Normal v03 remain exploratory examples, not final independent validation. No fresh, independently generated Attack and challenging Normal sessions were authorized or captured in this continuation, so final independent-validation success and baseline-versus-augmented improvement are not claimed.

## Isolated baseline replay for final holdouts

Offline replay used Suricata `8.0.3 RELEASE`, a copy of the existing isolated YAML with `baseline.rules`, and separate `/tmp/suricata-hybrid-baseline-20261111/{attack-k-none,normal-k-none}` output directories. Commands were:

```bash
suricata -T --init-errors-fatal -c /tmp/suricata-hybrid-baseline-20261111/isolated-baseline.yaml -l /tmp/suricata-hybrid-baseline-20261111/syntax
suricata -k none -r /tmp/hybrid-attack-v02.pcap -c /tmp/suricata-hybrid-baseline-20261111/isolated-baseline.yaml -l /tmp/suricata-hybrid-baseline-20261111/attack-k-none
suricata -k none -r /tmp/hybrid-normal-v03.pcap -c /tmp/suricata-hybrid-baseline-20261111/isolated-baseline.yaml -l /tmp/suricata-hybrid-baseline-20261111/normal-k-none
```

Attack produced 24 flows and zero baseline alerts. Normal produced 24 flows, 22 `ET INFO Python SimpleHTTP ServerBanner` alerts, and 109 `SURICATA TCPv4 invalid checksum` alerts. The latter are decoder/checksum artifacts from the captured HTTP traffic, not a scenario-specific reconnaissance verdict. Isolated EVE SHA256 values were `2efb4518eec7c8aeaffc49840d9b2ee830fc9629b48ba212976c7a6ce1cd0e10` (Attack) and `2a221006ea3bd65fe37c8546beeb4be183ba987e1653949becd5bd63f6d4cad5` (Normal). No production EVE file, rule file, service, or daemon was modified.

The hybrid review result is not convertible to a safe single RST Suricata rule: an RST-only candidate calibrated at one response would also match Normal v03's two legitimate closed-port controls, while Suricata rule syntax cannot express the required unique-port and completed-handshake conditions together. Candidate generation therefore remains correctly blocked.

Production Suricata and Filebeat remained active throughout. The owner verified after capture completion that `/usr/bin/tcpdump` has no file capability. No production service, sudoers configuration, or capability was changed in this continuation.

## Acceptance status

| Criterion | Status |
|---|---|
| Hybrid integrated into PCAP/ML worker | Achieved; review-only and provenance-checked |
| Independent Attack/Normal validation | Not achieved; v02/v03 are exploratory holdouts |
| Safe candidate Suricata rule generated | No; evidence gates correctly rejected it |
| Suricata Attack replay of candidate | Not run; no candidate existed |
| Suricata Normal replay of candidate | Not run; no candidate existed |
| Baseline versus augmented improvement | Not demonstrated |
