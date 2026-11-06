# Batch worker

This directory contains the review-only batch worker for the lab SYN anomaly pipeline.

## Local CLI

```bash
python backend/worker.py \
  --pcap data/raw/example.pcap \
  --src 192.168.10.10 \
  --dst 192.168.10.20 \
  --private-root data/private \
  --out-dir data/private/lab-runs/example-run \
  --manifest data/private/lab-runs/example-run/manifest.json
```

The worker validates:
- IPv4 addressing and source/destination separation
- PCAP existence and safe size limits
- manifest checksum and review-state compatibility
- output directory safety and in-root location checks
- duplicate-run and overwrite protection

The worker reuses `src/netids.pipeline.run(...)` and keeps all rule output in a review-only status. It never auto-deploys a Suricata rule.

## Safe local validation

```bash
python -m pip install -e .
python -m pytest tests/test_rule_review_safety.py tests/test_worker.py -q
```

## VM3 / ELK notes

The read-only local implementation is intentionally separate from the operational EVE -> Filebeat -> Logstash -> Elasticsearch -> Kibana path. Real VM deployment and ELK validation remain a separate owner-authorized step and are not represented as completed in this repository.
