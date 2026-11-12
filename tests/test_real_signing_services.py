import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from backend.owner_approval_service import (
    OwnerApprovalError,
    create_owner_approval,
    verify_owner_approval,
)
from backend.replay_attestation_service import (
    ReplayAttestationError,
    ReplayAttestationService,
    verify_replay_attestation,
)
from netids.lifecycle_attestation import verify_attestation
from backend.isolated_suricata_runtime import IsolatedRuntimeError, IsolatedSuricataRuntime


def _key(path: Path):
    private = Ed25519PrivateKey.generate()
    path.write_bytes(private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    public = path.with_suffix(".pub.pem")
    public.write_bytes(private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    return path, public


def _candidate():
    return {
        "candidate_id": "candidate-9103003",
        "run_id": "milestone-5-rst-20261112-v4",
        "sid": 9103003,
        "rule_sha256": "7" * 64,
        "pcap_sha256": "a" * 64,
        "model_sha256": "b" * 64,
        "calibration_sha256": "c" * 64,
        "decision_manifest_sha256": "d" * 64,
        "suricata_version": "8.0.3 RELEASE",
    }


def test_replay_attestation_round_trip_and_tamper_rejection(tmp_path):
    private, public = _key(tmp_path / "replay.pem")
    record = {"schema_version": "suricata_replay_attestation_v1", **_candidate(), "attack_alerts": 1, "normal_alerts": 0, "verified": True}
    signature = ReplayAttestationService.sign_record(record, private)
    path = tmp_path / "replay-attestation.json"
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    (tmp_path / "replay-attestation.sig").write_text(signature + "\n", encoding="ascii")
    assert verify_replay_attestation(path, tmp_path / "replay-attestation.sig", public)
    public_bytes = serialization.load_pem_public_key(public.read_bytes()).public_bytes(Encoding.Raw, PublicFormat.Raw)
    record["attestation_signature"] = signature
    assert verify_attestation(record, public_bytes, domain="isolated-replay-v1")
    record["normal_alerts"] = 1
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    assert not verify_replay_attestation(path, tmp_path / "replay-attestation.sig", public)


def test_replay_service_rejects_caller_supplied_success(tmp_path):
    private, _ = _key(tmp_path / "replay.pem")
    service = ReplayAttestationService(
        private_key=private,
        expected_sid=9103003,
        expected_rule_sha256="7" * 64,
        expected_model_sha256="b" * 64,
        expected_calibration_sha256="c" * 64,
        expected_decision_manifest_sha256="d" * 64,
        expected_suricata_version="8.0.3 RELEASE",
    )
    with pytest.raises(ReplayAttestationError, match="does not accept caller"):
        service.attest_from_verified_results({**_candidate(), "verified": True})


def test_owner_approval_requires_exact_scope_and_expiry(tmp_path):
    private, public = _key(tmp_path / "owner.pem")
    now = datetime.now(timezone.utc)
    record, signature = create_owner_approval(
        private_key=private,
        candidate=_candidate(),
        target_vm="suricata-vm1",
        isolated_runtime_id="isolated-lifecycle-9103003",
        interface="lo",
        operation="activate_once_then_rollback",
        approver_identity="owner@example.invalid",
        replay_evidence_sha256="e" * 64,
        approved_at=now,
        expires_at=now + timedelta(minutes=10),
        nonce="f" * 32,
        confirmation="ACTIVATE_ONCE_THEN_ROLLBACK",
    )
    used_nonces = set()
    assert verify_owner_approval(record, signature, public, now=now, expected_candidate=_candidate(), used_nonces=used_nonces)
    assert not verify_owner_approval(record, signature, public, now=now, expected_candidate=_candidate(), used_nonces=used_nonces)
    record["sid"] = 1
    assert not verify_owner_approval(record, signature, public, now=now)


def test_owner_approval_rejects_wrong_expected_candidate(tmp_path):
    private, public = _key(tmp_path / "owner.pem")
    now = datetime.now(timezone.utc)
    record, signature = create_owner_approval(
        private_key=private, candidate=_candidate(), target_vm="suricata-vm1",
        isolated_runtime_id="isolated-lifecycle-9103003", interface="lo",
        operation="activate_once_then_rollback", approver_identity="owner",
        replay_evidence_sha256="e" * 64, approved_at=now,
        expires_at=now + timedelta(minutes=10), nonce="f" * 32,
        confirmation="ACTIVATE_ONCE_THEN_ROLLBACK",
    )
    wrong = {**_candidate(), "sid": 1}
    assert not verify_owner_approval(record, signature, public, now=now, expected_candidate=wrong)


def test_owner_approval_never_auto_approves(tmp_path):
    private, _ = _key(tmp_path / "owner.pem")
    with pytest.raises(OwnerApprovalError, match="explicit typed confirmation"):
        create_owner_approval(
            private_key=private, candidate=_candidate(), target_vm="suricata-vm1",
            isolated_runtime_id="isolated-lifecycle-9103003", interface="lo",
            operation="activate_once_then_rollback", approver_identity="owner",
            replay_evidence_sha256="e" * 64,
            approved_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
            nonce="f" * 32, confirmation=None,
        )


def test_runtime_rejects_unmarked_or_production_root(tmp_path):
    with pytest.raises(IsolatedRuntimeError, match="isolated"):
        IsolatedSuricataRuntime(
            root=tmp_path / "production", config=tmp_path / "production" / "isolated.yaml",
            rules_dir=tmp_path / "production" / "rules", logs_dir=tmp_path / "production" / "logs",
            pidfile=tmp_path / "production" / "runtime" / "suricata.pid",
            socket_path=tmp_path / "production" / "runtime" / "suricata.sock",
        )


def test_runtime_rollback_uses_suricatasc_shutdown(tmp_path, monkeypatch):
    root = tmp_path / "isolated-runtime"
    rules = root / "rules"
    destination = rules / "candidate.rules"
    destination.parent.mkdir(parents=True)
    destination.write_text("alert tcp any any -> any any (sid:9103003;)\n", encoding="utf-8")
    runtime = IsolatedSuricataRuntime(
        root=root, config=root / "suricata.yaml", rules_dir=rules,
        logs_dir=root / "logs", pidfile=root / "runtime" / "suricata.pid",
        socket_path=root / "runtime" / "suricata.sock",
    )
    calls = []

    class Result:
        returncode = 0

    def fake_run(command, **kwargs):
        calls.append(command)
        return Result()

    monkeypatch.setattr("backend.isolated_suricata_runtime.subprocess.run", fake_run)
    rule_sha256 = hashlib.sha256(destination.read_text(encoding="utf-8").strip().encode("utf-8")).hexdigest()
    assert runtime.rollback(destination, 9103003, rule_sha256)
    assert calls == [["suricatasc", "-s", str(runtime.socket_path), "-c", "shutdown"]]
