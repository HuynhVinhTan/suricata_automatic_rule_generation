import json
import hashlib
import os
import sqlite3

import pytest

from netids.g3_lab_demo import (
    G3_DOMAIN,
    G3ReplayError,
    build_lab_demo_record_from_evidence,
    sign_lab_demo_record,
    verify_and_record_lab_demo,
)
from netids.lifecycle_ed25519 import generate_encrypted_keypair, public_key_fingerprint
from netids import g3_lab_cli
from scripts import g3_lab_build_record


PASSWORD = b"g3-test-passphrase"


def _manifest_sha256(manifest):
    return hashlib.sha256(
        json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()


_RECORD_MANIFEST = {
    "capture_interface": "eth1",
    "capture_duration_sec": 60,
    "pcap_sha256": "c" * 64,
    "review_only": True,
}


def _record():
    record = {
        "schema_version": "lab_demo_attestation_v1",
        "run_id": "g3-20261123T120000Z-01",
        "event_id": "g3-event-20261123T120000Z-01",
        "sequence": 1,
        "nonce": "a" * 64,
        "source_vm": "suricata-vm2",
        "target_vm": "suricata-vm3",
        "artifact_sha256": "b" * 64,
        "source_pcap_sha256": "c" * 64,
        "manifest": dict(_RECORD_MANIFEST),
        "evidence": {"classification": "review_only", "review_only": True, "window_count": 6},
    }
    record["manifest_sha256"] = _manifest_sha256(record["manifest"])
    return record


def test_lab_demo_signature_verifies_and_binds_lineage_in_sqlite(tmp_path):
    private, public = generate_encrypted_keypair(PASSWORD)
    fingerprint = public_key_fingerprint(public)
    envelope = sign_lab_demo_record(_record(), private, PASSWORD)

    result = verify_and_record_lab_demo(
        envelope, public, pinned_fingerprint=fingerprint,
        sqlite_path=tmp_path / "replay.sqlite3",
    )

    assert result["verified"] is True
    assert result["event_id"] == "g3-event-20261123T120000Z-01"
    with sqlite3.connect(tmp_path / "replay.sqlite3") as db:
        assert db.execute("SELECT COUNT(*) FROM verified_envelopes").fetchone()[0] == 1
        assert db.execute(
            "SELECT event_id, sequence, source_pcap_sha256, manifest_sha256 "
            "FROM verified_envelopes"
        ).fetchone() == (
            "g3-event-20261123T120000Z-01", 1, "c" * 64,
            _manifest_sha256(_RECORD_MANIFEST),
        )


def test_lab_demo_rejects_tampering_without_writing_replay_record(tmp_path):
    private, public = generate_encrypted_keypair(PASSWORD)
    fingerprint = public_key_fingerprint(public)
    envelope = sign_lab_demo_record(_record(), private, PASSWORD)
    tampered = json.loads(json.dumps(envelope))
    tampered["artifact_sha256"] = "e" * 64

    with pytest.raises(G3ReplayError, match="signature"):
        verify_and_record_lab_demo(
            tampered, public, pinned_fingerprint=fingerprint,
            sqlite_path=tmp_path / "replay.sqlite3",
        )
    assert not (tmp_path / "replay.sqlite3").exists()


@pytest.mark.parametrize("field,value", [
    ("event_id", "g3-event-other"),
    ("sequence", 2),
    ("source_pcap_sha256", "e" * 64),
    ("manifest_sha256", "f" * 64),
])
def test_lab_demo_rejects_tampered_signed_lineage(field, value, tmp_path):
    private, public = generate_encrypted_keypair(PASSWORD)
    fingerprint = public_key_fingerprint(public)
    envelope = sign_lab_demo_record(_record(), private, PASSWORD)
    tampered = dict(envelope)
    tampered[field] = value
    if field == "source_pcap_sha256":
        tampered["manifest"] = dict(tampered["manifest"], pcap_sha256=value)

    with pytest.raises(G3ReplayError, match="signature|manifest"):
        verify_and_record_lab_demo(
            tampered, public, pinned_fingerprint=fingerprint,
            sqlite_path=tmp_path / "replay.sqlite3",
        )
    assert not (tmp_path / "replay.sqlite3").exists()


def test_lab_demo_rejects_wrong_key(tmp_path):
    private, public = generate_encrypted_keypair(PASSWORD)
    _, wrong_public = generate_encrypted_keypair(PASSWORD)
    envelope = sign_lab_demo_record(_record(), private, PASSWORD)

    with pytest.raises(G3ReplayError, match="pinned|signature"):
        verify_and_record_lab_demo(
            envelope, wrong_public,
            pinned_fingerprint=public_key_fingerprint(wrong_public),
            sqlite_path=tmp_path / "replay.sqlite3",
        )


def test_lab_demo_replay_is_transactional_and_survives_reopen(tmp_path):
    private, public = generate_encrypted_keypair(PASSWORD)
    fingerprint = public_key_fingerprint(public)
    envelope = sign_lab_demo_record(_record(), private, PASSWORD)
    db_path = tmp_path / "replay.sqlite3"

    verify_and_record_lab_demo(envelope, public, pinned_fingerprint=fingerprint, sqlite_path=db_path)
    with pytest.raises(G3ReplayError, match="replay"):
        verify_and_record_lab_demo(envelope, public, pinned_fingerprint=fingerprint, sqlite_path=db_path)

    duplicate_event = _record()
    duplicate_event["run_id"] = "g3-20261123T120000Z-02"
    duplicate_event["nonce"] = "b" * 64
    duplicate_envelope = sign_lab_demo_record(duplicate_event, private, PASSWORD)
    with pytest.raises(G3ReplayError, match="replay"):
        verify_and_record_lab_demo(
            duplicate_envelope, public, pinned_fingerprint=fingerprint, sqlite_path=db_path
        )

    with sqlite3.connect(db_path) as db:
        assert db.execute("SELECT COUNT(*) FROM verified_envelopes").fetchone()[0] == 1


@pytest.mark.parametrize("value", [False, None])
def test_lab_demo_rejects_non_review_only_manifest(tmp_path, value):
    private, public = generate_encrypted_keypair(PASSWORD)
    record = _record()
    if value is None:
        record["manifest"].pop("review_only")
    else:
        record["manifest"]["review_only"] = value
    with pytest.raises(G3ReplayError, match="review-only"):
        sign_lab_demo_record(record, private, PASSWORD)


def test_g3_domain_and_key_provisioner_are_explicit(tmp_path, monkeypatch, capsys):
    assert G3_DOMAIN == "lab-demo-vm2-vm3-v1"
    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"
    monkeypatch.setattr(g3_lab_cli.getpass, "getpass", lambda _prompt: PASSWORD.decode())

    assert g3_lab_cli.provision_main([
        "--private-key", str(private_path), "--public-key", str(public_path),
    ]) == 0
    if os.name == "posix":
        assert private_path.stat().st_mode & 0o777 == 0o600
    assert public_path.read_bytes().startswith(b"-----BEGIN PUBLIC KEY-----")
    assert public_key_fingerprint(public_path.read_bytes()) in capsys.readouterr().out
    with pytest.raises(ValueError):
        g3_lab_cli.provision_main([
            "--private-key", str(private_path), "--public-key", str(tmp_path / "other.pem"),
        ])


def _evidence_files(tmp_path):
    capture_id = "capture-20261123T120000Z-0123456789abcdef"
    generator_id = "g4-attack-20261123T120001Z-fedcba9876543210"
    pcap = tmp_path / f"{capture_id}.pcap"
    pcap.write_bytes(b"verified-pcap-bytes")
    pcap_sha = hashlib.sha256(pcap.read_bytes()).hexdigest()
    native_manifest = {
        "schema_version": "pcap_handoff_manifest_v1",
        "pcap_sha256": pcap_sha,
        "source_ipv4": "192.168.10.20",
        "destination_ipv4": "192.168.10.10",
        "run_id": capture_id,
        "capture_metadata": {
            "packets": 24,
            "initial_syn": 24,
            "http_get_starts": 0,
            "snaplen": 262144,
            "capture_kind": "raw",
            "sealed_at": "2026-11-23T12:02:00Z",
        },
    }
    native_path = tmp_path / f"{capture_id}.manifest.json"
    native_bytes = (json.dumps(native_manifest, sort_keys=True) + "\n").encode()
    native_path.write_bytes(native_bytes)
    ready_path = tmp_path / f"{capture_id}.ready.json"
    ready_path.write_text(json.dumps({
        "schema_version": "pcap_handoff_ready_v1",
        "run_id": capture_id,
        "pcap_sha256": pcap_sha,
        "manifest_sha256": hashlib.sha256(native_bytes).hexdigest(),
    }), encoding="utf-8")
    generator = {
        "schema_version": "lab_slow_port_scan_v1",
        "run_id": generator_id,
        "scenario": "ATTACK",
        "source_ip": "192.168.10.20",
        "target_ip": "192.168.10.10",
        "started_at_utc": "2026-11-23T12:00:01Z",
        "ended_at_utc": "2026-11-23T12:01:00Z",
        "attempt_count": 24,
        "attempts": [{}] * 24,
    }
    generator_path = tmp_path / f"{generator_id}.json"
    generator_path.write_text(json.dumps(generator, sort_keys=True), encoding="utf-8")
    return {
        "capture_id": capture_id,
        "generator_id": generator_id,
        "pcap": pcap,
        "native_manifest": native_path,
        "ready_marker": ready_path,
        "generator_json": generator_path,
        "expected_pcap_sha256": pcap_sha,
        "expected_generator_sha256": hashlib.sha256(generator_path.read_bytes()).hexdigest(),
    }


def test_evidence_builder_preserves_native_and_canonical_digests(tmp_path):
    files = _evidence_files(tmp_path)
    record = build_lab_demo_record_from_evidence(
        **files,
        g3_run_id="g3-20261123T120003Z-01",
        event_id="g3-event-20261123T120003Z-01",
        sequence=0,
        nonce="d" * 64,
    )
    assert record["source_pcap_sha256"] == files["expected_pcap_sha256"]
    assert record["artifact_sha256"] == files["expected_generator_sha256"]
    assert record["evidence"]["native_manifest_sha256"] == record["evidence"]["ready_manifest_sha256"]
    assert record["manifest"]["review_only"] is True
    assert record["manifest_sha256"] == _manifest_sha256(record["manifest"])


@pytest.mark.parametrize("tamper", ["ready", "pcap", "generator"])
def test_evidence_builder_rejects_tampered_input_bytes(tmp_path, tamper):
    files = _evidence_files(tmp_path)
    if tamper == "ready":
        data = json.loads(files["ready_marker"].read_text())
        data["manifest_sha256"] = "e" * 64
        files["ready_marker"].write_text(json.dumps(data), encoding="utf-8")
    elif tamper == "pcap":
        files["pcap"].write_bytes(b"tampered-pcap")
    else:
        files["generator_json"].write_text("{\"tampered\": true}", encoding="utf-8")
    with pytest.raises(G3ReplayError, match="digest|checksum|generator|manifest|PCAP"):
        build_lab_demo_record_from_evidence(
            **files,
            g3_run_id="g3-20261123T120003Z-01",
            event_id="g3-event-20261123T120003Z-01",
            sequence=0,
            nonce="d" * 64,
        )


def test_evidence_builder_and_sqlite_replay_survive_restart(tmp_path):
    files = _evidence_files(tmp_path)
    record = build_lab_demo_record_from_evidence(
        **files,
        g3_run_id="g3-20261123T120003Z-01",
        event_id="g3-event-20261123T120003Z-01",
        sequence=0,
        nonce="d" * 64,
    )
    private, public = generate_encrypted_keypair(PASSWORD)
    envelope = sign_lab_demo_record(record, private, PASSWORD)
    db_path = tmp_path / "replay.sqlite3"
    verify_and_record_lab_demo(envelope, public, pinned_fingerprint=public_key_fingerprint(public), sqlite_path=db_path)
    with pytest.raises(G3ReplayError, match="replay"):
        verify_and_record_lab_demo(envelope, public, pinned_fingerprint=public_key_fingerprint(public), sqlite_path=db_path)


def test_evidence_builder_cli_writes_exclusive_record(tmp_path):
    files = _evidence_files(tmp_path)
    output = tmp_path / "record.json"
    args = [
        "--capture-id", files["capture_id"], "--generator-id", files["generator_id"],
        "--pcap", str(files["pcap"]), "--native-manifest", str(files["native_manifest"]),
        "--ready-marker", str(files["ready_marker"]), "--generator-json", str(files["generator_json"]),
        "--expected-pcap-sha256", files["expected_pcap_sha256"],
        "--expected-generator-sha256", files["expected_generator_sha256"],
        "--g3-run-id", "g3-20261123T120003Z-01",
        "--event-id", "g3-event-20261123T120003Z-01", "--sequence", "0",
        "--nonce", "d" * 64, "--output", str(output),
    ]
    assert g3_lab_build_record.main(args) == 0
    assert json.loads(output.read_text())["manifest"]["review_only"] is True
    with pytest.raises(ValueError, match="overwrite"):
        g3_lab_build_record.main(args)
