# Phase 2 + Phase 3 — evidence-based acceptance status (2026-11-07)

This file distinguishes **verified capture outputs** from implementation, derived data, and VM acceptance that still needs an operator. It is a live release checklist, **not a claim that the project is 100% deployed**.

## Phase 2 evidence ledger

| Scenario | New session | Traffic verified | PCAP structure | Raw SHA256 | Derived normalized SHA256 | Current gate |
|---|---|---|---|---|---|---|
| Normal Independent | `normal-independent-20261107-v02` | 61/61 HTTP success; PCAP 61 SYN + 61 GET `/` | 614 packets; snaplen 262144; 0 truncated/incomplete; 307 incoming valid; 306/307 outgoing checksum bad (TX offload) | `9ebed71c32bd4840ea30505f034df9b2ac321c60dd6f6e425b7b030343fcaacf` | `d1ab04f1389a00fd3194f2647374eaba5e07f97ac1996c73e9e85d4aa9a7041a` | **Capture and derived normalization PASS**, offline Suricata replay still pending |
| Normal Multiport | `normal-multiport-20261107-v02` | 48/48 HTTP success, 8 ports, 6 GET per port | 486 packets; snaplen 262144; 0 truncated/malformed; 244 incoming valid; 242/242 outgoing bad pre-offload | `ff6c8bed0cfd66a245e3c9d46843c454565ed878d6cd53b46197a89b0053e9bf` | `f1eda01ed155945307deaa5de719b5792d38977b29d1eb0c70959d20b277b2bf` | **Capture and derived normalization PASS**, offline replay pending |
| TCP Connect Recon | `tcp-connect-recon-20261107-v02` | Expected 96, **only 93 SYN/93 GET in PCAP, 95 server log**; missing final `/admin` on 18109–18111. Operator confirmed early Ctrl+C | 930 packets, snaplen 262144; 0 truncated/malformed; 465 incoming valid, 465/465 outgoing bad pre-offload | `db28e25e5bee253ea141bbce10a6b8240f2eb3a2c3c75d3846d1bcade8f21b8a` | **None** — do not normalize as completed 96-flow evidence | **INCOMPLETE; preserve V02; repeat as V03** |
| Normal Matched-12 | Proposed `normal-matched12-20261107-v02` | Not captured yet: plan 96 benign `/health` GET, eight per each of 12 ports | Not verified | Not available | Not available | **PENDING** |

All capture times should be logged in UTC. The older 2026-10-31 V01 datasets used `tcpdump -s 96` and must remain untouched; they have documented truncation and in some cases checksum faults. Do not relabel V01 or V02 incomplete data as fresh independent holdout. V02 generator timing and paths are newly defined and are not asserted to reproduce every byte of V01.

## Known baseline already working

- VM1: Suricata 8.0.3 active; 53,249 loaded rules (53,248 alert, 1 drop), known production rules checksum `30d7a02cd85f7f7544231a91008a20dedbb15ff0e11ca388ac07aa8d564bf36b` (verify again at final acceptance). Filebeat and separate production EVE ingestion path previously checked active. Both rejected lab SIDs `9102001` and `9102002` must remain absent.
- VM3: worker previously ran the known lab slow SYN-scan PCAP `381652cb04c14dea565dee61cb77b151bf80571c531c76501aff97c480420c03`, finding 26 initial SYNs, 6 windows, IF=5, AE=5, consensus=5. This is an integration smoke test, not independent false-positive or zero-day accuracy evidence. The `suricata-ai-summary` Elasticsearch index and `Suricata AI Analysis` Kibana dashboard were reported visible.
- Project GitHub PR #1 has the existing frozen-model/review-only PCAP batch worker and separate model/report provenance verification. No model retraining, rule auto-approval, or rule deployment is authorized.
- New code on PR #1 adds `backend/pcap_handoff.py`, `scripts/lab_http_96.py`, `scripts/pcap_checksum_normalize.py`, offline unit tests and a GitHub Actions CI job. These are **code artifacts**, not a VM deployment.

## Immediate repeatability: complete the two missing captures

1. On VM1 prepare a NEW, separate Recon V03 experiment directory and the original hash-verified 12-port `synthetic_services.py` from V01. Capture with `tcpdump -i ens33 -s 0` and filter only TCP between 192.168.10.20 and 192.168.10.10 on ports 18100–18111. Use a bounded timeout longer than the planned ~60-second client run. Do not interrupt until the Kali client prints its completion gate. Never write to `/var/log/suricata/eve.json` or overwrite Recon V02.
2. On Kali (with a copy of the source checkout or this one standalone stdlib client) run:

~~~bash
python3 -m scripts.lab_http_96 recon-v03 --result-file "$HOME/recon-v03-client.json"
~~~

Only after `SAFE_TO_STOP_CAPTURE: YES`, `http_success=96` and `http_failures=0` should the VM1 capture be finalized. If client result fails, preserve that incomplete session and choose a new experiment/run ID; do not claim full acceptance.
3. Repeat as independent Normal Matched-12 V02 capture with the same 12 temporary services and same full snaplen/timeout; Kali invokes:

~~~bash
python3 -m scripts.lab_http_96 matched12-v02 --result-file "$HOME/matched12-v02-client.json"
~~~

Expected 96 GET `/health` (8 each port) and 96 separate initial SYNs. Note the old Matched-12 V01 has **192** GET/flows; the new 96-request control is a newly specified experiment, NOT an exact reproduction. Record this distinction.
4. For each **finalized** PCAP, run the reusable normalizer in **dry-run** first, pinning its independently calculated raw SHA256 and `--expected-syn 96 --expected-get 96`. Check that `inbound_bad=0`, `truncated_records=0` and the outbound-bad count is coherent with VM1 TX checksum offload. Only then rerun with `--expected-bad-outbound <DRY_RUN_COUNT> --execute` to create a separately hashed `-checksum-normalized.pcap` and `.provenance.json`. This does not alter original PCAPs or NIC settings.
5. Run isolated offline Suricata `-T` and `-r` from a temporary config/rule copy against Normal and Recon separately. Save alert outputs in distinct non-production paths, count attack-vs-normal alerts and verify no decoder truncation or invalid TCP checksum signatures for normalized inputs. A syntax PASS is **not** evidence that a new rule is accurate or approved.

For the normalizer run with its arguments (example placeholders intentionally require observed values):

~~~bash
python3 -m scripts.pcap_checksum_normalize \
  --pcap "$PCAP" \
  --output "$DERIVED_PCAP" \
  --src 192.168.10.20 --dst 192.168.10.10 \
  --expected-sha256 "$RAW_SHA256" \
  --expected-syn 96 --expected-get 96
# Read-only: record outbound_bad_before from the JSON output.
# Repeat with --expected-bad-outbound VALUE --execute ONLY after review.
~~~

## Final release gates (cannot be claimed green without VM evidence)

- [ ] New Recon V03 and Matched12 V02 each 96/96 complete requests/SYN; sealed raw+derived hashes and no truncation.
- [ ] Independent checksum audit on both derived copies: no invalid inbound/outbound TCP checksums, raw unchanged.
- [ ] Isolated Suricata syntax/replay, Normal false-alert assessment, immutable baseline rules and rejected SIDs absent.
- [ ] VM1-to-VM3 SSH handoff, exact manifest/ready hashes, controlled VM3 worker execution, JSON summary provenance and receipt verified.
- [ ] AI summary indexed without touching production EVE; Kibana dashboard reflects controlled new run; Suricata/Filebeat remain active.
- [ ] End-to-end demonstration, failure-path demo, architecture diagram, reproducible commands and final research limitations documented.
- [ ] GitHub PR CI clean; operator reviews and merges PR intentionally. No auto merge or production deployment.

## Demo narrative

Show Suricata live status and original rule hash; demonstrate an already-finalized isolated PCAP; verify bundle SHA/manifest, dry-run transfer, then authorized VM3 transfer and worker execution; inspect `review.json`, `worker_summary.json`, `suricata-ai-summary` and the dashboard; show that `approved=false`/`deployed=false` and rejected candidate rules were never activated. Normal and attack data are bounded and labeled separately, and model scores are not advertised as independent generalization estimates. Record exact run IDs, UTC windows, all hashes, exit codes and any observed failures.

**Conclusion:** The code-level gap is being closed on GitHub; production-free three-VM integration and full Phase 2 acceptance still require execution on the actual VMs. The project is not 100% verified until all release gates above pass.
