# G3 LAB_DEMO_ONLY offline evidence — 2026-11-23

## Scope

This is repository-only evidence. It does not provision a VM2 key, transfer a
public key to VM3, modify a VM3 trust store, or send telemetry.

## Implementation

- Producer/signing boundary: `src/netids/g3_lab_demo.py`
- Installed CLI implementation: `src/netids/g3_lab_cli.py`
- Reviewable wrappers: `scripts/g3_lab_provision_key.py`,
  `scripts/g3_lab_sign.py`, `scripts/g3_lab_verify.py`
- Trust domain: `lab-demo-vm2-vm3-v1`
- Replay database: SQLite `verified_envelopes`, unique nonce/run/event/envelope
  identity, `BEGIN IMMEDIATE`, `synchronous=FULL`, journal mode `DELETE`
- Private key: encrypted PKCS8, exclusive creation, mode 0600; private key is
  never an output of verification and is not committed
- Public key: fingerprint is SHA256 of the raw Ed25519 public key and must be
  independently pinned before verification

## Signed record contract

The signed payload binds `run_id`, `event_id`, non-negative `sequence`,
`issued_at_utc`, `source_vm=suricata-vm2`, `target_vm=suricata-vm3`,
`artifact_sha256`, `source_pcap_sha256`, `manifest_sha256`, the complete
review-only `manifest` object, and review-only evidence. The manifest PCAP hash
must equal the signed source PCAP hash. Tampering any of these values invalidates
the Ed25519 signature or the metadata checks before SQLite mutation.

## Offline commands

From an installed editable package or a normal wheel installation:

```text
python -m pytest -q tests/test_g3_lab_demo.py
python -m compileall -q src/netids/g3_lab_demo.py src/netids/g3_lab_cli.py scripts/g3_lab_*.py
g3-lab-provision-key --help
g3-lab-sign --help
g3-lab-verify --help
```

The test suite covers valid signing and recording, artifact tampering,
event/sequence/PCAP/manifest tampering, wrong key, non-review-only metadata,
SQLite replay after a closed-and-reopened process, and exclusive key creation.

## Runtime status

The offline result is `G3_OFFLINE_READY`, not runtime `G3_PASS`. A future
bounded operation must generate the key on VM2, compare the displayed public
fingerprint independently, transfer only the public PEM and pinned fingerprint
to VM3, and then verify a real signed envelope into the VM3 SQLite ledger.
