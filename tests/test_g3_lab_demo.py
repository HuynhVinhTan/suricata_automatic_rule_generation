import json
import hashlib
import os
import sqlite3

import pytest

from netids.g3_lab_demo import (
    G3_DOMAIN,
    G3ReplayError,
    sign_lab_demo_record,
    verify_and_record_lab_demo,
)
from netids.lifecycle_ed25519 import generate_encrypted_keypair, public_key_fingerprint
from netids import g3_lab_cli


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

    with sqlite3.connect(db_path) as db:
        assert db.execute("SELECT COUNT(*) FROM verified_envelopes").fetchone()[0] == 1


def test_lab_demo_rejects_non_review_only_manifest(tmp_path):
    private, public = generate_encrypted_keypair(PASSWORD)
    record = _record()
    record["manifest"]["review_only"] = False
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
