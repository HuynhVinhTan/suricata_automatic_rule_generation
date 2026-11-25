# G6 latency instrumentation and evidence runbook

## Status boundary

This document prepares offline measurement and reporting for the owner-operated
G5 SID9103005 run. It does not report G5 or G6 runtime PASS. No SSH, SCP, sudo,
traffic generation, tcpreplay, signing, activation or rollback was performed
while preparing this commit.

The repository does not contain an authoritative exact definition of T0–T11.
It establishes only that activation-dependent T8–T11 remain NOT_MEASURED. The
mapping below is therefore explicitly proposed for future owner-reviewed
evidence; it must not be presented as a historical measurement contract.

## T0–T11 coverage matrix

| Stage | Definition | Host | Existing source | Clock type | Available evidence | Missing instrumentation / status |
|---|---|---|---|---|---|---|
| T0 | Capture start | VM1 | `backend/pcap_capture.py` status metadata | UTC wall-clock | Capture manifests contain bounded timestamps | No cross-host offset proof; proposed mapping |
| T1 | Capture sealing | VM1 | `backend/pcap_capture.py`, `backend/pcap_handoff.py` | monotonic/UTC | Sealed PCAP, manifest and ready hashes | No unified elapsed trace; proposed mapping |
| T2 | Handoff transport | VM1→VM3 | `backend/pcap_handoff.py` | UTC + verified clock offset | `.sent.json` receipt has `sent_at` | No verified receive-side offset/elapsed duration |
| T3 | Handoff receipt | VM3 | `backend/pcap_handoff.py` | UTC wall-clock | `.done.json` receipt has completion time | No paired transport trace |
| T4 | Worker queue wait | VM3 | `backend/worker.py` / ledger | monotonic | Ledger timestamps are available in selected historical evidence | No normalized queue boundary in current evidence |
| T5 | Worker processing | VM3 | `src/netids/lab_workflow.py`, `backend/worker.py` | monotonic | Local `LatencyTrace` covers continuous inference only | No complete verified G6 worker trace |
| T6 | Feature extraction | VM3 | `src/netids/pipeline.py` | monotonic | Pipeline `latency-trace.json` can contain `feature_extraction` | Only historical/local traces; no G5-linked observation |
| T7 | ML/DL inference | VM3 | `src/netids/pipeline.py` | monotonic | Pipeline trace can contain `model_inference` | No new runtime measurement |
| T8 | Hybrid evaluation and candidate validation | VM3 | `src/netids/pipeline.py`, `src/netids/rulegen.py` | monotonic | Pipeline trace contains Hybrid/rule-generation stages | No complete T0–T11 trace; activation-dependent contract remains unresolved |
| T9 | Replay attestation and owner approval wait | Owner/VM1 | `scripts/attest_frozen_rst_replay.py`, `scripts/approve_frozen_rst_activation.py` | UTC + monotonic | New G5 trace measures verification, not human waiting | Human approval wait remains `NOT_MEASURED`; no subtraction of wall clocks |
| T10 | Isolated activation and probes | VM1 | `scripts/operate_frozen_rst_once.py`, `src/netids/isolated_suricata_runtime.py` | monotonic | New signed G5 result trace records activation and each probe | Actual run has not occurred |
| T11 | Mandatory rollback and post-rollback verification | VM1 | `RuleLifecycle`, `IsolatedSuricataRuntime` | monotonic | New signed G5 result trace records rollback boundaries | Actual run has not occurred |

### Existing measurements

- The local pipeline already records feature extraction, model inference, port,
  handshake, Hybrid extraction/decision, rule generation and local artifact
  validation in `latency-trace.json`.
- Historical documentation reports VM3 EVE-to-ledger latency for 607 records:
  minimum `31.033256 s`, median `235.973714 s`, P95 `303.697609 s`, maximum
  `358.519941 s`. This is not a complete T0–T11 trace and is not re-used as a
  new G6 population measurement.
- No verified G5 signed runtime result, owner authorization, activation,
  probe, rollback or post-rollback measurement exists in this checkout.

## Offline aggregation

The aggregator accepts JSON evidence envelopes containing a `run_id` and a
`latency_trace` (or legacy-compatible `latency`) object. It validates trace
identity, UTC fields, monotonic duration values and clock metadata. Missing,
failed and `NOT_MEASURED` observations are retained separately; missing values
are never replaced with zero.

After the owner supplies a verified runtime evidence file, run locally:

```powershell
$env:PYTHONPATH = 'src'
python -m scripts.aggregate_latency `
  --evidence C:\g5-signed\sid9103005-runtime-evidence.json `
  --output-dir artifacts\g6_latency\sid9103005
```

Outputs:

- `latency_per_run.csv`
- `latency_stage_summary.csv`
- `latency_coverage.json`
- `latency_report.md`
- `evidence_manifest.json`

The aggregator does not cryptographically verify the G5 signature itself. The
owner must first verify the signed runtime result with the existing G5 verifier;
the manifest records input and output SHA256 values. A trace is accepted only
when its `run_id` exactly matches the evidence envelope.

## H17/H18 figures

Plotting is reusable and empirical-data-only:

```powershell
$env:PYTHONPATH = 'src'
python -m scripts.plot_latency_figures `
  --per-run artifacts\g6_latency\sid9103005\latency_per_run.csv `
  --summary artifacts\g6_latency\sid9103005\latency_stage_summary.csv `
  --coverage artifacts\g6_latency\sid9103005\latency_coverage.json `
  --output-dir artifacts\g6_latency\sid9103005\figures
```

The plotter emits high-resolution PNG and SVG figures with white backgrounds
and Vietnamese labels when valid measured observations exist. It writes
`figures_pending.json` when data are absent, Normal/Attack labels are missing,
or complete sequential T0–T11 measurements are not verified. It never creates
synthetic report figures.

H17 stage breakdown and H18 per-session figures become READY from measured
rows. H17 waterfall and H18 Normal-versus-Attack comparison remain PENDING
until the corresponding complete evidence is present.

## Owner-operated preparation runbook

The following checks are read-only preparation steps. They are not executed by
this offline implementation.

### Windows owner workstation

1. Verify the reviewed branch/commit and source tree with `git rev-parse HEAD`,
   `git status --short --branch -uall`, and `git diff --check`.
2. Verify public artifact hashes and the candidate/replay/owner/runtime identity
   bindings. Never copy private PEMs into Git or an archive.
3. After the owner completes the one-shot G5 operation, copy only the verified
   runtime evidence into a private local evidence directory and run the two
   offline commands above.
4. Capture thesis screenshots of the aggregation summary, coverage JSON and
   each generated H17/H18 figure. Label all pending charts as `PENDING`.

### VM1 (`suricata-vm1` / Ubuntu)

1. Locally check `hostname`, `date -u --iso-8601=ns`, `timedatectl show -p
   NTPSynchronized -p TimeUSec`, and `df -h /home/tanhv` without changing time
   synchronization.
2. Check the existing isolated root, candidate files, public keys and source
   release hashes read-only. Preserve the existing VM1 staging directory.
3. VM1 last observed free space is approximately 2.7 GB, below the previous
   3 GiB capture readiness requirement. Do not lower the guard and do not delete
   evidence; the owner must resolve storage readiness separately.
4. Use the existing G5 bridge only after fresh owner-signed evidence and the
   reviewed source release are present. The new runtime trace is written inside
   the signed runtime result; failures retain an unsigned failure trace.

### VM2 (Kali controlled lab traffic generator)

Run only read-only checks locally: `hostname`, `date -u --iso-8601=ns`,
`timedatectl show -p NTPSynchronized -p TimeUSec`, `df -h`, and inspect the
existing generator/probe metadata. Do not run tcpreplay, traffic generation,
sudo or cleanup as part of this preparation.

### VM3 (Ubuntu AI worker and ELK)

Run only read-only checks locally: `hostname`, `date -u --iso-8601=ns`,
`timedatectl show -p NTPSynchronized -p TimeUSec`, `df -h`, and inspect the
existing worker ledger/receipt directories. Do not start the worker, alter the
ledger, index evidence or combine historical runs.

## Source-only VM1 archive instruction

Do not archive the repository or transfer notebooks, datasets, checkpoints or
private evidence. The owner may stage only the tracked runtime closure from the
final reviewed commit. This command is prepared, not executed here:

```bash
FINAL_RELEASE_COMMIT="<final-reviewed-commit-sha>"
ARCHIVE="suricata-ai-g5-runtime-${FINAL_RELEASE_COMMIT}.tar"
git archive --format=tar --output="$ARCHIVE" "$FINAL_RELEASE_COMMIT" \
  src/netids/__init__.py \
  src/netids/g5_frozen_candidate.py \
  src/netids/isolated_suricata_runtime.py \
  src/netids/key_pins.py \
  src/netids/latency.py \
  src/netids/lifecycle_attestation.py \
  src/netids/lifecycle_ed25519.py \
  src/netids/rulegen.py \
  src/netids/rule_lifecycle.py \
  src/netids/trusted_replay.py \
  scripts/operate_frozen_rst_once.py \
  scripts/operate_isolated_once.py
sha256sum "$ARCHIVE"
```

The owner must verify the archive hash and extract into a fresh versioned VM1
release directory. No existing `.runtime-staging/` directory is replaced.
