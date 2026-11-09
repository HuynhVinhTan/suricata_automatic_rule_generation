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

## Worked example: already verified Normal Independent V02 derived PCAP

From a checkout of this PR branch on VM1 (Python 3.10+):

~~~bash
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
~~~

On VM3, inspect the actual checkout and create `data/private/incoming-pcaps` with mode 0700 **only if** that directory is under the validated `private_root`. Use its **absolute path** for `REMOTE_INBOX` in the VM1 commands. Do not send a test PCAP into any production EVE or Logstash directory.

VM1 transfer dry-run (no SSH activity):

~~~bash
python3 -m backend.pcap_handoff send \
  --outbox /home/tanhv/suricata-ai-outbox \
  --run-id normal-independent-v02-normalized \
  --remote-user tanhv --remote-host 192.168.10.30 \
  --remote-inbox "$REMOTE_INBOX"
~~~

After permission, key and directory checks, repeat with `--execute`. On VM3 from its actual repo checkout, first verify the incoming bundle without running models:

~~~bash
python3 -m backend.pcap_handoff consume \
  --input-root "$REMOTE_INBOX" \
  --private-root "$VM3_PRIVATE_ROOT" \
  --run-id normal-independent-v02-normalized
~~~

Then repeat with `--execute`, once the existing frozen-artifact worker preflight passes. To also write the dedicated summary, append `--elasticsearch-url http://192.168.10.30:9200` only after confirming the actual VM3 Elasticsearch endpoint and access. A matching 409 is verified by GET; all other conflict or connection outcomes fail closed and need investigation. Never force a duplicate run.

## Optional automation after single-run acceptance

VM1 can periodically execute the command below **only after the owner authorizes scheduling**:

~~~bash
python3 -m backend.pcap_handoff send \
  --outbox /home/tanhv/suricata-ai-outbox \
  --all-ready --remote-user tanhv --remote-host 192.168.10.30 \
  --remote-inbox "$REMOTE_INBOX" --execute
~~~

VM3 can independently process only finalized received bundles:

~~~bash
python3 -m backend.pcap_handoff consume \
  --input-root "$REMOTE_INBOX" --private-root "$VM3_PRIVATE_ROOT" \
  --all-ready --execute
~~~

Use separate, least-privilege systemd one-shot/timer units, reviewed by the owner, rather than a production Suricata hook. Do not enable timers based solely on unit tests. On a failed transfer, do not delete or overwrite `.partial` files before verifying target evidence.

## Acceptance gate

1. Phase 2: new complete Recon capture (V03), 96/96 SYN/GET; separate Matched-12 capture 96/96 GET; full snaplen and no truncated records. Preserve incomplete Recon V02 unchanged.
2. Offline Suricata `-T` and `-r` in temporary directories using frozen rules, evaluating Attack and Normal independently. No rule deployments and no false-positive claims without evidence.
3. VM1 -> VM3 PCAP SHA agreement, worker summary hashes and review flags, `.done.json` receipt, ES summary index and Kibana dashboard observation. Existing EVE pipeline unaffected.
4. Confirm prod Suricata and Filebeat still active, old rule hash unchanged, and preserve UTC timestamps. Slow-scan regression is known traffic, not independent model accuracy evidence; do not rerun or tune against official UNSW-NB15 test.

Offline tests: `python -m pytest -q tests/test_phase3_pcap_handoff.py`. See [Phase 2/3 acceptance evidence](PHASE2_PHASE3_ACCEPTANCE_20261107.md) for the known results and outstanding VM gates.
