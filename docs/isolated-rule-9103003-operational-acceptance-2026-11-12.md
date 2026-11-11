# SID 9103003 — one-time isolated VM1 activation / rollback runbook

## Authorization boundary

User consent is limited to one Suricata 8.0.3 activation followed by mandatory rollback on suricata-vm1 loopback lo, alert-only SID 9103003. The consent does not authorize modifications to production Suricata, Filebeat, EVE-to-ELK, firewall, sudoers, file capabilities or interfaces.

No real SSH/VM1 session or key provisioning has yet occurred in this PR. No activation/rollback may be marked PASS solely from CI or synthetic tests.

Immutable identity:
- SID: 9103003
- Original rule SHA256: 7182bb328ce4ed1230c6de9b20c825d458b8c224a494d6b2a60063cca5ec21df
- Model SHA256: 206dadafc8d6cd96e21d838a52211d9b06d4a6ec541ea5c9a9ae8a6724ffbf5d
- Calibration SHA256: 814e17006c5cfee433477128e9d29abf7e403e28948d78a968c46c800b67e060
- Decision SHA256: c7dffd3021d0c0195789e45c369f30108186753076b95586a2d80c9c744b579a
- Isolated root: /home/tanhv/suricata-rule-review/isolated-lifecycle-9103003
- Engine: Suricata 8.0.3 RELEASE, interface lo, action alert only.
- SID 9103003 is an RST telemetry proxy, NOT the complete Python Hybrid detector.
- The six holdouts are reused as reproducibility checks, NOT new independent tests.

## A. Read-only preflight — stop on mismatch

1. Fetch this PR's feature branch on the owner's Windows development environment, preserving all local modifications.
2. Via the owner's existing SSH session, READ-ONLY inspect VM1 hostname, Suricata version, systemctl Suricata/Filebeat state and PIDs, production YAML and active rules SHA256, actual capture interfaces and tcpdump capability state.
3. Confirm production does not capture lo, tcpdump capabilities remain revoked and production processes are active. Do not change privileges or production configuration to make this pass.
4. Discover the ORIGINAL SID 9103003 rule from the real reviewed lab artifacts and independently verify its exact raw SHA256. Do not reconstruct or modify the rule to fit the target SHA.
5. Locate the six original PCAPs, three Attack and three Normal, and verify their hashes against the hard-pinned mapping in src/netids/trusted_replay.py.
6. Confirm the existing VM1 account has adequate disk space and can run already-installed suricata, suricatasc and tcpreplay on lo without installing tools, changing privileges or touching ens33/ens37. If missing, STOP.
7. Prepare an isolated YAML inside the exact root using the previously proven isolated configuration only after reviewing all YAML paths: no output to production, eve-log filename eve.json, af-packet and pcap references only lo, no syslog, separate socket/PID/logs/rules.

## B. Generate TWO private, independent encrypted Ed25519 keys

On OWNER Windows machine (never VM1):

    python -m scripts.lifecycle_keys --role owner --private data/private/owner-9103003.pem --public data/private/owner-9103003.pub.pem

On VM1 (never Windows):

    python3 -m scripts.lifecycle_keys --role replay --private /home/tanhv/.config/suricata-ai/replay-9103003.pem --public /home/tanhv/.config/suricata-ai/replay-9103003.pub.pem

The commands prompt for distinct strong passphrases. Files are created exclusively; never overwrite. VM1 private key/directory permissions must be 0600/0700; on Windows verify NTFS ACLs allow only the owner. Never reveal private keys or passphrases in chat, logs, GitHub or Notion.

Exchange ONLY public PEMs. Verify independently pinned public SHA256 fingerprints, never trust a key supplied solely by the candidate.

## C. Register original candidate as PROPOSED only

Use scripts/register_generated_rule_review.py on the exact existing rule-handoff artifacts. Provide its required artifact directory, run ID, original calibration manifest and owner-pinned hash, baseline rule file and owner-pinned hash, audit path and isolated root. Add:

    --private-candidate-output /home/tanhv/suricata-rule-review/isolated-lifecycle-9103003/evidence/candidate.json

This outputs the complete provenance-bound candidate privately. It does NOT approve, deploy or activate. Verify the resulting SID and raw rule SHA. If the worker candidate differs, STOP; do not invent a replacement. The command is local-only and leaves existing review artifacts unchanged.

## D. Run and sign six REAL offline PCAP replays on VM1

Create private isolated replay-manifest.json with schema_version suricata_replay_manifest_v1, the exact candidate_id/run_id/pcap_sha256 from candidate.json, sid 9103003, the rule/model/calibration/decision hashes above, and exactly six cases. Every case has id, scenario, original absolute pcap_path and pcap_sha256, matching the six hard-pinned values in src/netids/trusted_replay.py. The source candidate PCAP must be one of the three original Attack holdouts.

Verify manifest bytes and record its SHA256. Then invoke:

    python3 -m scripts.attest_lab_replay --manifest PATH_TO_PRIVATE_MANIFEST --manifest-sha256 VERIFIED_MANIFEST_SHA256 --rule ORIGINAL_RULE_FILE --isolated-yaml /home/tanhv/suricata-rule-review/isolated-lifecycle-9103003/isolated.yaml --isolated-root /home/tanhv/suricata-rule-review/isolated-lifecycle-9103003 --replay-private /home/tanhv/.config/suricata-ai/replay-9103003.pem --replay-public /home/tanhv/.config/suricata-ai/replay-9103003.pub.pem --output /home/tanhv/suricata-rule-review/isolated-lifecycle-9103003/evidence/replay-attestation.json

The signer runs actual Suricata -T plus six isolated -r PCAP replay subprocesses, parses EVE events and SID counts, requires each Attack SID alert and no Normal SID alert, and signs only after ALL gates pass. Original PCAPs and raw EVE remain private. No network listener is created. On failure, no successful attestation is issued.

## E. Separate owner approval on Windows

Copy only replay-attestation.json and the pinned replay PUBLIC key to the owner's Windows workspace. Inspect signed evidence then invoke:

    python -m scripts.approve_isolated_activation --replay-attestation data/private/replay-attestation.json --replay-public data/private/replay-9103003.pub.pem --owner-private data/private/owner-9103003.pem --owner-public data/private/owner-9103003.pub.pem --candidate-id EXACT_VERIFIED_CANDIDATE_ID --run-id EXACT_VERIFIED_RUN_ID --approver-identity OWNER_ID --output data/private/owner-approval-9103003.json

It displays exact target, rule hash, interface, rollback requirement, asks for a typed confirmation, and unlocks owner encrypted private key locally. It signs a nonce-bound, 15-minute, one-time authorization scoped to operation activate, runtime suricata-vm1:isolated-lifecycle-9103003:lo and mandatory rollback. This step does NOT activate anything.

Transfer only the signed owner-approval JSON and owner PUBLIC key to VM1, never the private key.

## F. Actual VM1 operation — ONE time, mandatory rollback

Run locally on VM1, only AFTER both independent signatures and exact provenance are verified. Use:

    python3 -m scripts.operate_isolated_once --help

Required arguments:
--candidate-file, --replay-attestation-file, --owner-approval-file,
--replay-public-file, --owner-public-file, --production-yaml,
--production-rules, --isolated-yaml, --attack-pcap, --normal-pcap,
--audit-path, --replay-private-file, --evidence-output.

Use actual discovered production YAML and active rule paths as READ-ONLY before/after snapshot inputs, never as destination files. The operator must select actual original Attack01 and Normal01 PCAPs from the six validated holdouts, matching their hard-pinned hashes.

The CLI checks authorization signatures, candidate hash, rule text, model and calibration provenance, production before state, Suricata 8.0.3, hostname, lo and private root. It starts ONLY a new Popen-owned isolated Suricata subprocess with --af-packet=lo, a dedicated --unix-socket, --pidfile, -l directory and -S exclusive isolated rules file. It uses blocking ruleset-reload-rules, verifies exactly one loaded rule and requires real SID 9103003 EVE alerts after tcpreplay --intf1=lo, with no SID alerts on the Normal PCAP.

Mandatory rollback restores the empty isolated ruleset, issues another blocking reload on the SAME isolated UNIX socket, requires zero loaded rules and a new Attack replay with zero SID alerts, then stops the owned isolated daemon. No production PID is ever signaled, and no systemctl write command is used.

If real EVE proof is missing, any reload fails, or any hash/VM/interface differs: STOP and report FAILED/UNVERIFIED. Never relax tests to force acceptance. If a rollback fails, preserve logs and report FAILED; do not claim cleanup success.

Additional fail-closed requirements for the one-time VM1 command:

- --audit-path must be exactly /home/tanhv/suricata-rule-review/isolated-lifecycle-9103003/audit/owner-once.jsonl. This is a persistent nonce-replay ledger; never rotate or delete it to reuse an approval.
- --production-yaml must be the actual /etc/suricata/suricata.yaml on VM1, with last verified SHA256 6224bc7d0bc04d97c4282f54a71e0736341341aa82c530fe22aed3da28814d72. If it differs, stop and re-establish a read-only reviewed baseline before attempting this operation.
- --production-rules must be an actual production rules file under /var/lib/suricata/rules or /etc/suricata/rules. The existing production rules must NOT already contain SID 9103003.
- Activation cannot rely on merely writing the rule file: the runtime requires exactly one successfully loaded rule and actual SID-alerting EVE. Rollback requires exactly zero loaded rules plus new EVE events proving an Attack replay occurred with no SID 9103003 alert.
- No operator may run this command a second time with the same signed nonce, even on a different audit path.

## G. Acceptance and evidence handling

The success report must include exact run/candidate IDs, pinned public-key fingerprints, signed replay and owner records, production before/after SHA/PID/status, isolated daemon PID/socket, Suricata version, activation EVE hash and SID counts, verified zero rules/SID after rollback, and confirmed isolated process shutdown.

Do not upload original PCAPs, private keys or credential-containing logs to Git. Commit only scrubbed SHA/status evidence after a human review.

PASS requires REAL replay attestation + REAL owner signature + REAL isolated activation evidence + REAL verified rollback + production invariants unchanged.
BLOCKED if SSH/VM/private files/signing keys/tooling are unavailable.
FAIL if the rule hash, replay results, active ruleset, rollback, or production before/after invariants mismatch.

M4–M6 remain accepted for six bounded experiments, not live production generalization.
