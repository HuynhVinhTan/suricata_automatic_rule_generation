# Defense demonstration runbook

## Safe fallback demonstration

Use the fallback unless the Owner has separately approved a live demo and the VM readiness gates have been completed. The fallback uses authentic preserved artifacts and no VM, SSH, Suricata, replay, activation, signing, authorization, or nonce operation.

1. Open `FROZEN_INPUT_MANIFEST.json`; show exact artifact and signature verification results.
2. Show the candidate ID and the explicit false review/deployment flags.
3. Show the signed six-case replay result: TP=3, FP=0, FN=0, TN=3.
4. Explain the terminal G5R4 failure and that all historical flow records were emitted at shutdown.
5. Show the observer correction, focused regression tests, and full-suite result.
6. Show the latency table, pointing out historical stage measurements and `NOT_MEASURED` runtime entries.
7. End with the conclusion that the candidate remains review-only and runtime acceptance is blocked.

Do not show private evidence, raw PCAP contents, model binaries, signing keys, authorization files, passphrases, credentials, or nonce values. Do not present the G4 replay as a live G5 activation.

## Optional Owner-approved live demonstration

Do not run this section unless the Owner separately approves the demo and confirms that it is isolated from production. Keep VM2 powered off until this decision. Verify the VM2 address and login name from the actual lab configuration before connecting; do not infer either from historical notes.

Run read-only checks locally in each VM's Owner-operated terminal. Do not use an SSH command pasted into Codex or provide credentials in chat.

### VM1

```bash
hostname
ip -4 -o addr show dev ens33
suricata -V
systemctl is-active suricata
systemctl is-active filebeat
systemctl list-timers --all --no-pager
df -h /home/tanhv
sha256sum /home/tanhv/g5-signed/sid9103005-candidate.json
sha256sum /home/tanhv/g5-signed/sid9103005-replay-attestation.json
sha256sum /home/tanhv/suricata-ai-outbox/capture-20261124T084151Z-3f1cd58c154c2528/capture-20261124T084151Z-3f1cd58c154c2528.pcap
sha256sum /home/tanhv/suricata-ai-outbox/capture-20261124T084302Z-5a0b32ad74afadb8/capture-20261124T084302Z-5a0b32ad74afadb8.pcap
sha256sum /home/tanhv/suricata-ai-outbox/capture-20261124T084417Z-bd88394699af2c08/capture-20261124T084417Z-bd88394699af2c08.pcap
sha256sum /home/tanhv/suricata-ai-outbox/capture-20261124T084647Z-127d1bad4c6ca17c/capture-20261124T084647Z-127d1bad4c6ca17c.pcap
sha256sum /home/tanhv/suricata-ai-outbox/capture-20261124T090352Z-287e0018439fa23a/capture-20261124T090352Z-287e0018439fa23a.pcap
sha256sum /home/tanhv/suricata-ai-outbox/capture-20261124T090513Z-2b3262e5b0271900/capture-20261124T090513Z-2b3262e5b0271900.pcap
```

Compare candidate, replay, and six PCAP hashes with `FROZEN_INPUT_MANIFEST.json`. The six expected PCAP hashes in A1/N1/etc order are listed there. Use the documented non-live readiness validator only after confirming reviewed paths and exact hashes. It runs Suricata version and syntax checks; it must not start the daemon, replay traffic, or consume authorization.

### VM2

First confirm its approved address, username, and powered state from the actual lab configuration. If the demo is not approved, leave the VM off. Do not run traffic generation or packet replay as part of a defense demo without the separate approval package.

### VM3 and ELK

Read-only checks in the VM3 terminal:

```bash
hostname
python3 --version
df -h /
sha256sum /home/tanhv/suricata-ai-showcase/private/lab-models/lab_syn_anomaly_v0_1/models.joblib
sha256sum /home/tanhv/suricata-ai-private/lab-models/lab_syn_anomaly_v0_1/models.joblib
curl -fsS 'http://192.168.10.30:9200/_cat/indices/suricata*?v'
curl -sS -I 'http://192.168.10.30:5601/'
```

Historical notes identify VM3 as `192.168.10.30`, `suricata-eve-*` and `suricata-ai-summary` indices, and the `Suricata AI Analysis` Kibana dashboard. These endpoints returned Elasticsearch HTTP 200 and Kibana HTTP 302 in a historical audit; confirm current reachability before presenting them. In Kibana Discover, select the existing AI summary index pattern and filter using a run ID that is visible in the preserved evidence. Do not create or modify an index or dashboard during the demo. The two model hashes must match `206dadaf...` and each other; hashing does not load the model.

## Screenshot checklist

- Architecture diagram with three VM roles and the production/research boundary.
- Candidate manifest showing candidate ID and review-only booleans.
- Verifier output showing the frozen six-case result.
- Observer test output and full test count.
- Latency table with measured and `NOT_MEASURED` rows visible.
- If an Owner-approved live demo occurs, capture the native readiness report and the authorized runtime verdict separately. Do not fabricate screenshots or hide a failure.
