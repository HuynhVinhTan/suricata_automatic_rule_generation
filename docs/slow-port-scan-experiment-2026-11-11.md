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

`src/netids/hybrid_review.py` adds a separate review-only decision layer. It does not alter the five-feature contract, model files, or IF/AE thresholds. Calibration now requires `configs/hybrid_normal_calibration.json`, exact PCAP SHA256 values, explicit Normal ground truth, source/destination endpoints, and authentic capture metadata proving packet completeness, full snaplen, and zero capture drops. The five existing lab-session PCAPs have no authentic per-capture manifest or log with those integrity facts, so the persistent manifest records their hashes and labels but deliberately marks capture metadata unknown. Calibration therefore fails closed and no hybrid threshold is accepted. `tcp-connect-recon-20261031-v01` remains excluded because its name is ambiguous and no explicit ground-truth manifest was found. Whole-PCAP distinct-port totals remain reporting-only; any calibrated classification uses the 60-second sliding-window maximum.

An earlier private derived file, `data/private/lab-runs/slow-port-independent-20261111/hybrid-evaluation.json`, recorded hybrid-looking classifications using retrospective completeness values. Those classifications are exploratory only and are not current validated results because the calibration references lack authentic capture manifests/logs. Its SHA256 was `a090437b3b0f549c76f36d6b6eb6c7a43d469314856a2a7f32023fa56f6debf2`.

The current worker does not accept those historical classifications. Its fresh runs fail closed until calibration provenance is recovered:

| Session | ML consensus | Hybrid classification | Result |
|---|---:|---|---|
| Attack v02 | 5/5 | `unavailable_missing_calibration` | Capture-integrity provenance unknown |
| Normal v03 | 5/5 | `unavailable_missing_calibration` | Capture-integrity provenance unknown |

The distinction is hybrid protocol evidence, not improved standalone IF/AE accuracy. The layer always returns condition-level explanations and keeps `approved=false`, `deployable=false`, and `deployed=false`. Incomplete capture evidence is classified as ambiguous and cannot pass.

Fresh worker runs `hybrid-worker-attack-v02-20261111-r3` and `hybrid-worker-normal-v03-20261111-r3` used the existing PCAPs without overwriting earlier evidence. Both had standalone IF=5, AE=5, consensus=5; both hybrid classifications were `unavailable_missing_calibration`, with calibration status `rejected` and reason `Hybrid calibration capture metadata is unknown`. Source PCAP, feature CSV, and frozen model SHA256 links verified, and `approved=false`, `deployable=false`, `deployed=false` were exact booleans. Attack v02 and Normal v03 remain exploratory examples, not final independent validation; one Attack and one Normal PCAP are not statistically meaningful independent evaluation.

## Historical calibration recovery matrix

The matrix below is read-only evidence. A readable PCAP does not prove zero capture drops or complete capture records.

| Reference | PCAP SHA256 / declared snaplen | Ground truth | Endpoints / interface / times | Completeness / drops | Decision |
|---|---|---|---|---|---|
| `normal-train.pcap` | `b79b45a8c62394a1fbb7284b4c3beead4139f51ab30438db5ea4df1bea46036a` / 262144 | `NORMAL` rows in `syn_windows_10s_normal-train.csv` (SHA `0674f57db0bf77b4411a93d0b27f46dc31558acf3450c2d8aab7c2ec7a477841`); original generator label unknown | Packet endpoints observable; original allowlist, interface, and start/end unknown | Unknown; no original manifest/log; zero drops not proven | **UNKNOWN — reject** |
| `normal-cal.pcap` | `3920256b68ac424b2296c62554d89637f32fba18ffa9fac4c3a62cb6d2cec5a0` / 262144 | `NORMAL` rows in `syn_windows_10s_normal-cal.csv` (SHA `bec7eb0253a944a4b435611d6af26cb9987f39fea456684b95cce1e0fd80671d`); original generator label unknown | Packet endpoints observable; original allowlist, interface, and start/end unknown | Unknown; no original manifest/log; zero drops not proven | **UNKNOWN — reject** |
| `normal-independent.pcap` | `27fe3158b29568db084fbb9c06528fcc82192f1655561a4a15dd02446f3d3442` / 96 | Directory/documentation label only; no original ground-truth log found | Packet endpoints observable; original allowlist, interface, and start/end unknown | Full snaplen **CONTRADICTED** by declared 96-byte snaplen and the V01 note in `docs/PHASE2_PHASE3_ACCEPTANCE_20261107.md` (SHA `64a3900f2495242d23d55786cfcb84e636d79e8c0355090f1bae8d42a403aff8`) | **CONTRADICTED — reject** |
| `normal-matched12.pcap` | `00488e39e6be54c7e261373b17b5223ea8eff4ccae2c827ec3d9b6cae1dd683b` / 96 | Directory/documentation label only; no original ground-truth log found | Packet endpoints observable; original allowlist, interface, and start/end unknown | Full snaplen **CONTRADICTED** by declared 96-byte snaplen and the V01 note above | **CONTRADICTED — reject** |
| `normal-multiport.pcap` | `494a100b1ad47f1d15f570f7940ab6e0abce02c0b86dda7eddc5ebd04d334736` / 96 | Directory/documentation label only; no original ground-truth log found | Packet endpoints observable; original allowlist, interface, and start/end unknown | Full snaplen **CONTRADICTED** by declared 96-byte snaplen and the V01 note above | **CONTRADICTED — reject** |

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
| Hybrid integrated into PCAP/ML worker | Achieved; review-only, provenance-checked, and fail-closed |
| Independent Attack/Normal validation | Achieved for six fresh bounded-lab holdouts; v02/v03 remain exploratory |
| Safe candidate Suricata rule generated | No; evidence gates correctly rejected it |
| Suricata Attack replay of candidate | Not run; no candidate existed |
| Suricata Normal replay of candidate | Not run; no candidate existed |
| Baseline versus augmented improvement | Not demonstrated |

The fresh calibration and holdout record supersedes the earlier recovery blocker. The calibrated result is still bounded to this VM1/VM2 lab and does not establish production generalization.

## Historical fresh-calibration plan and resulting evidence

The following was the pre-capture authorization plan. Its named calibration
and holdout runs are now complete; the plan remains here to preserve scope:

1. Capture independent Normal calibration sessions with a full-snaplen classic Ethernet PCAP and a separate immutable session manifest. Include one ordinary single-service session, one multiport benign service-check session, and one challenging benign session containing expected closed-port RSTs/failed connections.
2. Record generator ground truth, source/target allowlists, UTC start/end times, interface, tcpdump command/options, declared snaplen, clean exit status, and `pcap_stats`/kernel drop counters in the capture-time log. A readable PCAP alone is insufficient.
3. Seal each PCAP with its SHA256 and independently verify packet counts, endpoint direction, snaplen/truncation, and zero drops. Reject any incomplete or ambiguous session.
4. Freeze the hybrid thresholds from only the accepted Normal calibration set, then evaluate fresh independent Attack and challenging Normal holdouts with new run IDs. Do not use either holdout to tune thresholds.

The authorized fresh calibration and holdout sessions are complete. The final
two-service calibration PCAP has SHA256
`1195656c8c53bf01f07bb7d6277210ba0fef4b7cfa6dca394f11f13ce4f0ce54`; three
earlier incomplete attempts were retained and rejected. Frozen thresholds are
ports `4`, RST/window `3`, and handshake failures `2`.

The six fresh sessions passed integrity. Standalone IF/AE flagged every window
in both classes. The Python hybrid classified all three fresh Attack sessions
as `reconnaissance_consistent` and all three fresh Normal sessions as
`anomalous_not_reconnaissance`. No executable Suricata rule was generated or
approved: the hybrid conditions are not expressible by one safe signature, and
the existing SYN-burst candidates remain rejected for Normal false positives.
Production Suricata, Filebeat, EVE-to-ELK, the frozen model and official
benchmarks were unchanged.
