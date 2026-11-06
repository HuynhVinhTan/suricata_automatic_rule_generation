# Review-only PCAP batch worker

`worker.py` processes one finalized PCAP through the existing five-feature
PCAP-derived SYN-window pipeline. It does not consume EVE flow records, train
models, deploy Suricata rules, or resume partial runs.

## Input contract

The PCAP must be inside an operator-designated input directory. The default is
`data/private/incoming-pcaps`; create that directory and place only completed
captures there. The worker resolves the path and rejects traversal and symlink
escapes.

Each invocation requires a safe run ID and either:

- `--expected-sha256` with the independently verified 64-character PCAP hash,
  or
- `--manifest` with a JSON manifest that binds the PCAP hash, run ID, source
  and destination IPv4 addresses.

Manifest example:

```json
{
  "schema_version": "pcap_ai_worker_v0_1",
  "pcap_sha256": "REPLACE_WITH_VERIFIED_64_CHARACTER_SHA256",
  "source_ipv4": "192.168.10.20",
  "destination_ipv4": "192.168.10.10",
  "run_id": "lab-run-001",
  "capture_metadata": {
    "captured_at": "2026-11-06T10:00:00Z"
  }
}
```

The manifest is schema-validated and its checksum is recomputed against the
PCAP before processing. A manifest is not a digital signature or proof of the
capture's origin.

## Local invocation

Run from the repository root in an environment where `netids` and the project's
declared Python dependencies are available. PowerShell example using an
independently verified hash:

```powershell
python backend\worker.py --pcap data\private\incoming-pcaps\scan-001.pcap --input-root data\private\incoming-pcaps --src 192.168.10.20 --dst 192.168.10.10 --private-root data\private --run-id scan-001 --expected-sha256 YOUR_VERIFIED_SHA256
```

Manifest alternative:

```powershell
python backend\worker.py --pcap data\private\incoming-pcaps\scan-001.pcap --input-root data\private\incoming-pcaps --src 192.168.10.20 --dst 192.168.10.10 --private-root data\private --run-id scan-001 --manifest data\private\incoming-pcaps\scan-001.manifest.json
```

The worker writes to `data/private/lab-runs/<run-id>/`. Existing output,
failure records, or active run locks for the same ID prevent reprocessing and
are never overwritten. Partial pipeline directories remain failed evidence;
the worker does not resume or clean them automatically.

Before calling the existing `netids.pipeline.run(...)`, the worker checks the
frozen model checksum and report contract, Normal train/calibration CSV
checksums and contents, and historical proposal provenance. Missing or
mismatched artifacts stop processing. No model or threshold is changed.

## Optional Elasticsearch summary

To publish a successful run summary to the dedicated `suricata-ai-summary`
index, add `--elasticsearch-url http://ELASTICSEARCH_HOST:9200`. This uses an
HTTP `create` request with a stable document ID; conflicts and connection
failures are reported and produce a nonzero CLI exit. The indexed document is
allowlisted summary metadata only: it excludes PCAP bytes, source/destination
IPs, local paths, private rule text, and raw exception messages.

Do not point this option at the lab Elasticsearch instance until the owner
authorizes remote access and the storage/service preflight is complete. Local
automated tests mock HTTP calls and do not contact Elasticsearch.

## Focused local validation

```powershell
python -m pytest tests\test_worker.py tests\test_pipeline_port_diversity_review.py tests\test_rule_review_safety.py -q
```

The worker tests use synthetic PCAP bytes and temporary artifacts. The
rule-safety test reads existing private frozen references but does not modify
them. Do not rerun the locked official UNSW test as part of worker validation.

## Separate review and deployment gates

The AI worker is the PCAP/SYN path. Operational Suricata EVE ingestion remains
separate: Suricata EVE JSON → Filebeat → Logstash → Elasticsearch → Kibana.
Neither path automatically enables a rule.

When separately authorized, validate a proposed rule only with an isolated
temporary Suricata configuration and output directory:

```text
suricata -T -c <temporary-config> -l <temporary-output>
suricata -r <bounded-test.pcap> -c <temporary-config> -l <temporary-output>
```

Compare bounded Attack and Normal replay alerts and record false-alert
evidence. Syntax success does not approve or deploy a candidate. No Suricata,
VM, SSH, Elasticsearch, or Kibana service operation has been run by the local
worker tests.
