"""Synthetic Ed25519 trust-boundary tests. NEVER run or authorize real Suricata."""

import hashlib
from datetime import datetime, timedelta, timezone

import pytest

from netids.lifecycle_ed25519 import (
    generate_encrypted_keypair, sign_record, verify_record, public_key_fingerprint,
)
from netids.rule_lifecycle import RuleLifecycle, LifecycleError
from netids.trusted_replay import (
    SID, RULE_SHA, MODEL_SHA, CAL_SHA, DECISION_SHA, EXPECTED_CASES,
    ReplayGateError, attest_six_holdouts,
)
from scripts.approve_isolated_activation import build_owner_authorization

PASSWORD = b"synthetic-ed25519-test-passphrase-123"


def _keys():
    return generate_encrypted_keypair(PASSWORD)


def test_sign_verify_domain_separation_wrong_key_and_tampering():
    private, public = _keys()
    other_private, other_public = _keys()
    record = {"sid": SID, "approved": False, "run_id": "synthetic-test"}
    signed = sign_record(record, private, PASSWORD, domain="isolated-replay-v1")
    assert verify_record(signed, public, domain="isolated-replay-v1")
    assert not verify_record(signed, other_public, domain="isolated-replay-v1")
    assert not verify_record(signed, public, domain="isolated-owner-approval-v1")
    assert not verify_record({**signed, "approved": True}, public, domain="isolated-replay-v1")
    assert not verify_record({**signed, "attestation_ed25519": "***"}, public, domain="isolated-replay-v1")
    assert public_key_fingerprint(public) != public_key_fingerprint(other_public)
    with pytest.raises(ValueError):
        sign_record(signed, private, PASSWORD, domain="isolated-replay-v1")
    with pytest.raises(ValueError):
        sign_record(record, other_private, PASSWORD, domain="invalid-domain")


def test_keygen_rejects_weak_passphrase_and_invalid_password():
    with pytest.raises(ValueError, match="passphrase"):
        generate_encrypted_keypair(b"short")
    private, _ = _keys()
    with pytest.raises(ValueError):
        sign_record({"a": 1}, private, b"wrong", domain="isolated-owner-approval-v1")


def _signed_replay_and_candidate(private):
    run_id = "worker-attack-holdout-01-20261111"
    candidate_id = hashlib.sha256(f"{run_id}:{SID}:{RULE_SHA}".encode()).hexdigest()
    cases = [
        {"run_id": k, "scenario": scenario, "pcap_sha256": sha, "candidate_sid_alerts": 1 if scenario == "attack" else 0}
        for k, (scenario, sha) in EXPECTED_CASES.items()
    ]
    record = {
        "schema_version": "isolated_replay_attestation_v1",
        "candidate_id": candidate_id,
        "run_id": run_id,
        "pcap_sha256": EXPECTED_CASES[run_id][1],
        "sid": SID,
        "rule_sha256": RULE_SHA,
        "model_sha256": MODEL_SHA,
        "calibration_sha256": CAL_SHA,
        "decision_manifest_sha256": DECISION_SHA,
        "syntax_authenticated": True,
        "attack_replay_passed": True,
        "normal_replay_passed": True,
        "normal_false_positive_count": 0,
        "threshold": 3,
        "experiment_id": "synthetic-offline-test",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "cases": cases,
    }
    return sign_record(record, private, PASSWORD, domain="isolated-replay-v1"), candidate_id, run_id


def test_owner_signature_requires_trusted_replay_and_independent_keys():
    replay_private, replay_public = _keys()
    owner_private, owner_public = _keys()
    record, candidate_id, run_id = _signed_replay_and_candidate(replay_private)
    auth = build_owner_authorization(
        record, replay_public_pem=replay_public,
        owner_private_pem=owner_private, owner_private_password=PASSWORD,
        owner_public_pem=owner_public,
        approver_identity="synthetic-owner@example.invalid",
        candidate_id=candidate_id, run_id=run_id, nonce="a" * 32,
        now=datetime.now(timezone.utc),
    )
    assert auth["operation"] == "activate"
    assert auth["interface"] == "lo"
    assert auth["rollback_required"] is True
    assert verify_record(auth, owner_public, domain="isolated-owner-approval-v1")
    assert not verify_record(auth, replay_public, domain="isolated-owner-approval-v1")
    with pytest.raises(ValueError):
        build_owner_authorization(
            {**record, "normal_false_positive_count": 1},
            replay_public_pem=replay_public, owner_private_pem=owner_private,
            owner_private_password=PASSWORD, owner_public_pem=owner_public,
            approver_identity="owner", candidate_id=candidate_id, run_id=run_id,
            nonce="b" * 32,
        )


def test_ed25519_lifecycle_requires_signed_replay_and_owner_approval(tmp_path):
    replay_private, replay_public = _keys()
    owner_private, owner_public = _keys()
    rule = (
        'alert tcp any any -> 192.0.2.10 any '
        '(msg:"synthetic signature only"; sid:9103999; rev:1;)'
    )
    run_id = "synthetic-run"
    rule_sha = hashlib.sha256(rule.encode()).hexdigest()
    pcap_sha = "a" * 64
    candidate = {
        "run_id": run_id, "pcap_sha256": pcap_sha,
        "model_sha256": "b" * 64, "calibration_sha256": "c" * 64,
        "sid": 9103999, "rule": rule, "rule_sha256": rule_sha,
        "approved": False, "deployable": False, "deployed": False,
    }
    lifecycle = RuleLifecycle(
        tmp_path / "audit.jsonl", isolated_root=tmp_path / "isolated-lab",
        replay_verification_key=replay_public, owner_verification_key=owner_public,
        attestation_mode="ed25519",
    )
    candidate = lifecycle.create_candidate(candidate)
    lifecycle.transition(candidate, "VALIDATING")
    evidence = {
        "candidate_id": candidate["candidate_id"], "run_id": run_id,
        "sid": candidate["sid"], "rule_sha256": rule_sha,
        "pcap_sha256": pcap_sha, "model_sha256": "b" * 64,
        "calibration_sha256": "c" * 64, "experiment_id": "synthetic-test",
        "syntax_authenticated": True, "attack_replay_passed": True,
        "normal_replay_passed": True, "normal_false_positive_count": 0,
        "threshold": 3,
    }
    with pytest.raises(LifecycleError, match="Authenticated"):
        lifecycle.record_validation(candidate, evidence)
    evidence = sign_record(evidence, replay_private, PASSWORD, domain="isolated-replay-v1")
    lifecycle.record_validation(candidate, evidence)
    lifecycle.transition(candidate, "AWAITING_APPROVAL")
    now = datetime.now(timezone.utc)
    auth = {
        "candidate_id": candidate["candidate_id"], "run_id": run_id,
        "sid": candidate["sid"], "rule_sha256": rule_sha,
        "environment": "isolated-lab", "isolated_root": str(lifecycle.isolated_root),
        "operation": "activate", "approver_identity": "synthetic",
        "nonce": "a" * 32, "approved_at": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(minutes=14)).isoformat(),
    }
    with pytest.raises(LifecycleError, match="Authenticated"):
        lifecycle.approve(candidate, auth)
    lifecycle.approve(
        candidate, sign_record(auth, owner_private, PASSWORD, domain="isolated-owner-approval-v1")
    )
    result = lifecycle.stage(candidate, tmp_path / "isolated-lab")
    assert result["status"] == "dry_run"
    assert lifecycle.verify_audit() > 4
    assert candidate["approved"] is False


def test_real_replay_does_not_run_when_owner_pinned_manifest_is_wrong(tmp_path):
    root = tmp_path / "isolated-lifecycle-9103003"
    root.mkdir()
    manifest = root / "manifest.json"
    manifest.write_text('{"schema_version":"suricata_replay_manifest_v1"}')
    private, _ = _keys()
    with pytest.raises(ReplayGateError, match="manifest hash"):
        attest_six_holdouts(
            manifest_path=manifest, expected_manifest_sha256="0" * 64,
            rule_file=root / "rule.rules", isolated_yaml=root / "isolated.yaml",
            isolated_root=root, private_key_pem=private,
            private_key_password=PASSWORD,
            suricata_binary="/definitely/missing/suricata",
        )
