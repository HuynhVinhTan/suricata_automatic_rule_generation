# Phase 3: review-only VM1 -> VM3 PCAP handoff

**State:** Code and offline synthetic tests implemented. Live VM deployment and three-VM end-to-end acceptance are **not yet verified**. No change to production Suricata, Filebeat, ELK routing, model files, thresholds or candidate rule activation is performed by this code.

## Data path

VM2 controlled traffic -> VM1 separately finalized PCAP -> sealed bundle -> verified SSH/scp handoff -> VM3 dedicated incoming PCAP directory -> frozen `backend.worker` -> optional `suricata-ai-summary` Elasticsearch index -> existing Kibana AI dashboard.

Suricata EVE -> Filebeat -> Logstash -> Elasticsearch stays separate. Do not replay experiment data into `/var/log/suricata/eve.json`. Rejected SIDs 9102001 and 9102002 must stay undeployed. A `needs_review` status is not authorization to enable a rule.

The bundle contains `<run-id>.pcap`, `<run-id>.manifest.json` and `<run-id>.ready.json`. The manifest and ready marker bind SHA256, source/destination IPs, run ID, packet/SYN/GET counts and capture kind. A checksum-normalized PCAP is a labeled **derived artifact**, never a replacement for original evidence. SHA256/SSH provide integrity across the lab trust boundary but the manifest is not a digital signature.

## Fail-closed behavior

- Explicit independently verified PCAP SHA256 and expected SYN count (plus optional GET count) gate sealing. This rejects the known incomplete Recon V02 (93 SYN / 93 GET instead of 96). Classic Ethernet PCAP with full snaplen, complete records and at least one initial SYN is required. Max 512 MiB. PCAP-NG and other link types are not accepted.
- `bundle` refuses existing run IDs, copies source bytes without altering them, verifies source and copy hashes, publishes ready last. Failure leaves evidence without a ready marker. Input symlinks/path escapes are refused.
- `send` is a dry-run without `--execute`. Execution requires an existing authorized VM3 incoming directory, pinned SSH host key and noninteractive SSH. It stages into `.partial`, verifies remote hashes and publishes files without overwrite, `.ready.json` last. Successful transfers have local `.sent.json` acknowledgments. Every existing acknowledgment is checked against its bundle and destination before being skipped; inconsistent receipts stop the batch. Failed/incomplete remote transfers are not auto-deleted.
- `consume` is a dry-run without `--execute`. It checks PCAP, manifest and ready hashes again, runs the existing frozen worker, optionally indexes only its summary, then writes `.done.json`. If worker output exists without a receipt, the receiver validates summary identity/checksum, frozen-model and feature/prediction provenance, and review-only safety fields. Valid completed output can be published/reconciled without rerunning the worker; incomplete, failed or mismatched output remains blocked and is not overwritten.
- Each `--all-ready` invocation considers at most 10 **pending** runs, after validating all existing receipts and bundles; completed historical runs do not consume the limit. Inconsistent/orphan receipts fail the batch rather than being silently skipped.
- Elasticsearch `409` is accepted only after an explicit GET confirms the stable document ID, index and exact allowlisted summary content. Missing, unreachable or conflicting documents fail closed. No timer is enabled by these commands or tests.

## Before connecting VMs

On VM1 inspect `hostname`, `ip -4 addr show ens33`, `systemctl is-active suricata`, free disk and PCAP SHA256. On VM3 confirm the actual repo checkout, private root, frozen artifacts, free disk and existing AI worker, and independently pin the SSH host key for `192.168.10.30`. **Do not assume VM3 repo path without verification.** Passwordless SSH and a dedicated writable incoming directory must be explicitly approved and set up by its owner.

## Optional bounded VM1 capture

`backend.pcap_capture` is a distinct, opt-in capture-to-seal workflow. It does
not read or write Suricata EVE, change Suricata/Filebeat/Logstash configuration,
or install or enable a timer. The already-installed sender and VM3 worker
timers automate batches of **already sealed/received** bundles; they do not
start packet capture. The example capture timer below is for a future operator
decision only. Do not install or enable it as part of this change.

The helper is deliberately fixed to classic Ethernet PCAP on `ens33`, snaplen
262144, and the exact BPF expression
`tcp and src host 192.168.10.20 and dst host 192.168.10.10`. The normal duration
is 60 seconds; the only runtime option is `--duration-seconds` from 1 through 60. A Linux `RLIMIT_FSIZE` hard limit and a post-exit size check enforce the
64 MiB per-file maximum. Before launch it requires at least 3 GiB free on both
the private capture root and sender outbox. It retains at most 16 distinct
capture run IDs and at most 1 GiB combined raw-plus-bundle bytes. These limits
are fixed in code, not exposed as command options. Reaching a limit refuses
new captures; there is no automatic deletion or rotation.

The private raw root is fixed at `/var/lib/suricata-ai-capture`; the sender
outbox is fixed at `/home/tanhv/suricata-ai-outbox`. Both must already exist,
be non-symlink directories owned by the service account, and have mode 0700.
The raw root must be separate from the outbox. Confirm the VM1 sender account,
outbox path, and ownership before using this example; update the two constants
and reviewed unit together if the actual deployment differs. A fresh run uses
a UTC timestamp plus a 64-bit random suffix and exclusive directory creation.
An exclusive lock prevents concurrent runs from bypassing the retention cap.
Do not remove a stale lock until an operator verifies no capture process is
running and inspects the retained evidence.

### Install and manual run

These are future operator steps, not commands run for this change. First verify
the approved checkout path, the `tanhv` service account, the exact sender
outbox, and `/usr/bin/tcpdump` on VM1. Install only the private root; do not
change the outbox owner or permissions unless the sender owner approves it:

```bash
id tanhv
command -v tcpdump
stat -c '%U:%G %a %n' /home/tanhv/suricata-ai-outbox
sudo install -d -o tanhv -g tanhv -m 0700 /var/lib/suricata-ai-capture
stat -c '%U:%G %a %n' /var/lib/suricata-ai-capture /home/tanhv/suricata-ai-outbox
```

Create `/etc/systemd/system/suricata-ai-capture.service` only after review.
Use the real checkout path for `WorkingDirectory`; the example grants only
`CAP_NET_RAW` to the non-root sender account, constrains writable paths, and
does not grant a shell or additional network capabilities:

```ini
[Unit]
Description=Bounded Suricata AI lab PCAP capture and sealing
After=network.target

[Service]
Type=oneshot
User=tanhv
Group=tanhv
WorkingDirectory=/opt/suricata-ai-project
ExecStart=/usr/bin/python3 -m backend.pcap_capture --duration-seconds 60
UMask=0077
TimeoutStartSec=75
TimeoutStopSec=10
KillSignal=SIGINT
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_RAW
AmbientCapabilities=CAP_NET_RAW
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/lib/suricata-ai-capture /home/tanhv/suricata-ai-outbox
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_PACKET
```

Do not add file capabilities to tcpdump or grant `CAP_NET_ADMIN`. Validate the
unit and its paths before any run. The helper sends no SSH traffic and does not
process packets itself; the only sealing path is the existing audited
`backend.pcap_handoff.bundle` function.

After explicit operator approval and while the authorized VM2 lab source is
ready, perform one bounded manual run through the reviewed unit (not by
enabling a timer):

```bash
sudo systemctl daemon-reload
sudo systemctl start suricata-ai-capture.service
sudo systemctl status --no-pager suricata-ai-capture.service
sudo journalctl -u suricata-ai-capture.service --no-pager -n 50
```

For a one-off duration other than 60 seconds, edit the unit to a value from 1
through 60 and review it again before starting it. The CLI has no BPF, path,
interface, snaplen, output filename, or shell-command override. A clean capture
is independently hashed and structurally/SYN-audited before the existing
bundle function writes its manifest and ready marker. The original PCAP remains
unchanged under the private root. No SYN or no packets produces a
`non_processed` status and no bundle. Truncated/corrupt data, size overflow,
tcpdump failure, interruption, or stop timeout retains bounded evidence and
does not publish a ready marker. A sender can consider only a bundle with a
valid ready marker; partial outbox files are not sendable. Check
`status.json` under the raw run directory and the journal output. Do not infer
scenario labels, model accuracy, or checksum validity from these captures.

### Optional timer example and rollback

Only after the manual VM1-to-VM3 acceptance below, an operator may create
`/etc/systemd/system/suricata-ai-capture.timer` for review. The example is
intentionally **not enabled**:

```ini
[Unit]
Description=Optional bounded Suricata AI lab capture schedule

[Timer]
OnCalendar=*-*-* *:0/10:00
AccuracySec=1s
Persistent=false
Unit=suricata-ai-capture.service

[Install]
WantedBy=timers.target
```

Do not run `systemctl enable` for this timer by default. If an operator later
authorizes it, first verify that the VM2 source and timing are appropriate and
that the 60-second collection window will not conflict with the already
scheduled sender. To roll back, stop the capture service, disable/stop the
capture timer only if an operator had enabled it, remove only these two unit
files, then run `systemctl daemon-reload`. Preserve private raw evidence,
sealed bundles, sender receipts, and worker receipts; do not alter the EVE/ELK
units. If limits are reached, archive and manually remove old capture runs only
after review and after verifying no corresponding sender/worker operation is
active. A stale `.capture.lock` also requires this review before removal.

### Capture acceptance

- Confirm the service account owns both approved 0700 roots and that both
  storage locations have at least 3 GiB free. Confirm the process receives
  only `CAP_NET_RAW` and uses the exact interface, filter, snaplen, and duration.
- With mocked tcpdump only, `python -m pytest -q tests/test_pcap_capture.py`
  covers empty/no-SYN input, malformed/truncated PCAP, BPF/config rejection,
  stop timeout, size and disk caps, retention, duplicate/invalid IDs,
  interruption, permission failure, and repeated execution without overwrite.
- For an operator-approved manual capture, require a clean tcpdump exit,
  complete classic Ethernet PCAP, a successful independent audit, matching
  raw/bundle SHA256, preserved original evidence, and a valid ready marker.
  Confirm no ready marker on every failed/non-processed path.
- Verify the existing sender and worker timers process only the sealed bundle;
  verify the EVE -> Filebeat -> Logstash path and frozen artifacts remain
  unchanged. Do not enable a capture timer based on offline tests alone.

No live capture, systemd change, SSH, official frozen benchmark, model/threshold
change, checksum normalization, or rule activation is performed by this
implementation.

## Worked example: already verified Normal Independent V02 derived PCAP

From a checkout of this PR branch on VM1 (Python 3.10+):

```bash
mkdir -p -m 700 /home/tanhv/suricata-ai-outbox
python3 -m backend.pcap_handoff bundle \
  --pcap /home/tanhv/suricata-rule-review/normal-independent-20261107-v02/normal-independent-checksum-normalized.pcap \
  --input-root /home/tanhv/suricata-rule-review \
  --outbox /home/tanhv/suricata-ai-outbox \
  --run-id normal-independent-v02-normalized \
  --src 192.168.10.20 --dst 192.168.10.10 \
  --expected-sha256 d1ab04f1389a00fd3194f2647374eaba5e07f97ac1996c73e9e85d4aa9a7041a \
  --expected-syn 61 --expected-get 61 \
  --capture-kind checksum-normalized
```

On VM3, inspect the actual checkout and create `data/private/incoming-pcaps` with mode 0700 **only if** that directory is under the validated `private_root`. Use its **absolute path** for `REMOTE_INBOX` in the VM1 commands. Do not send a test PCAP into any production EVE or Logstash directory.

VM1 transfer dry-run (no SSH activity):

```bash
python3 -m backend.pcap_handoff send \
  --outbox /home/tanhv/suricata-ai-outbox \
  --run-id normal-independent-v02-normalized \
  --remote-user tanhv --remote-host 192.168.10.30 \
  --remote-inbox "$REMOTE_INBOX"
```

After permission, key and directory checks, repeat with `--execute`. On VM3 from its actual repo checkout, first verify the incoming bundle without running models:

```bash
python3 -m backend.pcap_handoff consume \
  --input-root "$REMOTE_INBOX" \
  --private-root "$VM3_PRIVATE_ROOT" \
  --run-id normal-independent-v02-normalized
```

Then repeat with `--execute`, once the existing frozen-artifact worker preflight passes. To also write the dedicated summary, append `--elasticsearch-url http://192.168.10.30:9200` only after confirming the actual VM3 Elasticsearch endpoint and access. A matching 409 is verified by GET; all other conflict or connection outcomes fail closed and need investigation. Never force a duplicate run.

## Optional automation after single-run acceptance

VM1 can periodically execute the command below **only after the owner authorizes scheduling**:

```bash
python3 -m backend.pcap_handoff send \
  --outbox /home/tanhv/suricata-ai-outbox \
  --all-ready --remote-user tanhv --remote-host 192.168.10.30 \
  --remote-inbox "$REMOTE_INBOX" --execute
```

VM3 can independently process only finalized received bundles:

```bash
python3 -m backend.pcap_handoff consume \
  --input-root "$REMOTE_INBOX" --private-root "$VM3_PRIVATE_ROOT" \
  --all-ready --execute
```

Use separate, least-privilege systemd one-shot/timer units, reviewed by the owner, rather than a production Suricata hook. Do not enable timers based solely on unit tests. On a failed transfer, do not delete or overwrite `.partial` files before verifying target evidence.

## Acceptance gate

1. Phase 2: new complete Recon capture (V03), 96/96 SYN/GET; separate Matched-12 capture 96/96 GET; full snaplen and no truncated records. Preserve incomplete Recon V02 unchanged.
2. Offline Suricata `-T` and `-r` in temporary directories using frozen rules, evaluating Attack and Normal independently. No rule deployments and no false-positive claims without evidence.
3. VM1 -> VM3 PCAP SHA agreement, worker summary hashes and review flags, `.done.json` receipt, ES summary index and Kibana dashboard observation. Existing EVE pipeline unaffected.
4. Confirm prod Suricata and Filebeat still active, old rule hash unchanged, and preserve UTC timestamps. Slow-scan regression is known traffic, not independent model accuracy evidence; do not rerun or tune against official UNSW-NB15 test.

Offline tests: `python -m pytest -q tests/test_phase3_pcap_handoff.py`. See [Phase 2/3 acceptance evidence](PHASE2_PHASE3_ACCEPTANCE_20261107.md) for the known results and outstanding VM gates.
