"""Synthetic contract tests: never authorize or activate production Suricata."""

import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from netids.rule_lifecycle import LifecycleError, RuleLifecycle

# Test fixtures only. Real attestation keys must be private and independent.
REPLAY_TEST_KEY = b"synthetic-replay-verifier-key-not-for-lab-use-0001"
OWNER_TEST_KEY = b"synthetic-owner-approval-key-not-for-lab-use-0002"


def _sign(data, key, domain):
    envelope = dict(data)
    payload = (
        b"suricata-ai:" + domain.encode("ascii") + b"\0"
        + json.dumps(
            envelope, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")
    )
    envelope["attestation_hmac"] = hmac.new(key, payload, hashlib.sha256).hexdigest()
    return envelope


def _lifecycle(tmp_path, *, existing_sids=()):
    return RuleLifecycle(
        tmp_path / "audit.jsonl",
        isolated_root=tmp_path / "lab",
        existing_sids=existing_sids,
        replay_verification_key=REPLAY_TEST_KEY,
        owner_verification_key=OWNER_TEST_KEY,
        attestation_mode="legacy-hmac",
    )


def _candidate(sid=9103999):
    rule = (
        f'alert tcp any any -> 192.0.2.10 any '
        f'(msg:"synthetic contract test"; sid:{sid}; rev:1;)'
    )
    return {
        "run_id": "run-001",
        "pcap_sha256": "a" * 64,
        "model_sha256": "b" * 64,
        "calibration_sha256": "c" * 64,
        "sid": sid,
        "rule": rule,
        "rule_sha256": hashlib.sha256(rule.encode("utf-8")).hexdigest(),
        "approved": False,
        "deployable": False,
        "deployed": False,
    }


def _replay(candidate):
    return {
        "syntax_authenticated": True,
        "attack_replay_passed": True,
        "normal_replay_passed": True,
        "normal_false_positive_count": 0,
        "candidate_id": candidate["candidate_id"],
        "run_id": candidate["run_id"],
        "experiment_id": "synthetic-contract-test",
        "sid": candidate["sid"],
        "rule_sha256": candidate["rule_sha256"],
        "pcap_sha256": candidate["pcap_sha256"],
        "model_sha256": candidate["model_sha256"],
        "calibration_sha256": candidate["calibration_sha256"],
        "threshold": 3,
    }


def _validated(lifecycle):
    candidate = lifecycle.create_candidate(_candidate())
    lifecycle.transition(candidate, "VALIDATING")
    evidence = _sign(_replay(candidate), REPLAY_TEST_KEY, "isolated-replay-v1")
    lifecycle.record_validation(candidate, evidence)
    lifecycle.transition(candidate, "AWAITING_APPROVAL")
    return candidate


def _owner_approval(lifecycle, candidate, *, operation="stage", nonce="d" * 32):
    now = datetime.now(timezone.utc)
    record = {
        "candidate_id": candidate["candidate_id"],
        "run_id": candidate["run_id"],
        "sid": candidate["sid"],
        "rule_sha256": candidate["rule_sha256"],
        "environment": "isolated-lab",
        "isolated_root": str(lifecycle.isolated_root),
        "operation": operation,
        "nonce": nonce,
        "approver_identity": "synthetic-owner@example.invalid",
        "approved_at": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(minutes=15)).isoformat(),
    }
    return _sign(record, OWNER_TEST_KEY, "isolated-owner-approval-v1")


def _approved(lifecycle, *, operation="stage"):
    candidate = _validated(lifecycle)
    lifecycle.approve(candidate, _owner_approval(lifecycle, candidate, operation=operation))
    return candidate


def _runtime(*, activation=True, verified=True, rollback=True, rollback_verified=True):
    return SimpleNamespace(
        validate=lambda rule: True,
        activate=lambda path, sid, sha: activation,
        verify_active=lambda sid, sha: verified,
        rollback=lambda path, sid, sha: rollback,
        verify_rollback=lambda sid, sha: rollback_verified,
    )


def test_review_only_candidate_requires_approval_and_proves_audit(tmp_path):
    lifecycle = _lifecycle(tmp_path)
    candidate = lifecycle.create_candidate(_candidate())
    with pytest.raises(LifecycleError, match="approval"):
        lifecycle.stage(candidate, tmp_path / "lab")
    lifecycle.transition(candidate, "VALIDATING")
    with pytest.raises(LifecycleError, match="Sensitive transition"):
        lifecycle.transition(candidate, "VALIDATED_FOR_REVIEW")
    with pytest.raises(LifecycleError, match="Authenticated"):
        lifecycle.record_validation(candidate, _replay(candidate))
    lifecycle.record_validation(
        candidate, _sign(_replay(candidate), REPLAY_TEST_KEY, "isolated-replay-v1")
    )
    lifecycle.transition(candidate, "AWAITING_APPROVAL")
    lifecycle.approve(candidate, _owner_approval(lifecycle, candidate))
    assert lifecycle.stage(candidate, tmp_path / "lab")["status"] == "dry_run"
    assert not list((tmp_path / "lab").glob("*.rules"))
    assert lifecycle.verify_audit() >= 6
    assert candidate["approved"] is False
    assert candidate["deployable"] is False
    assert candidate["deployed"] is False


def test_unsigned_and_spoofed_owner_approval_rejected(tmp_path):
    lifecycle = _lifecycle(tmp_path)
    candidate = _validated(lifecycle)
    record = _owner_approval(lifecycle, candidate)
    record["approver_identity"] = "spoofed-owner@example.invalid"
    with pytest.raises(LifecycleError, match="Authenticated owner"):
        lifecycle.approve(candidate, record)
    with pytest.raises(LifecycleError, match="Caller-provided"):
        lifecycle.approve(
            candidate, record, authorization_verifier=lambda _: True
        )
    assert candidate["state"] == "AWAITING_APPROVAL"


def test_replay_attestation_must_bind_exact_rule_and_hash(tmp_path):
    lifecycle = _lifecycle(tmp_path)
    candidate = lifecycle.create_candidate(_candidate())
    lifecycle.transition(candidate, "VALIDATING")
    evidence = _replay(candidate)
    evidence["pcap_sha256"] = "0" * 64
    with pytest.raises(LifecycleError, match="provenance"):
        lifecycle.record_validation(
            candidate, _sign(evidence, REPLAY_TEST_KEY, "isolated-replay-v1")
        )
    evidence = _replay(candidate)
    evidence["normal_false_positive_count"] = 1
    with pytest.raises(LifecycleError, match="Invalid"):
        lifecycle.record_validation(
            candidate, _sign(evidence, REPLAY_TEST_KEY, "isolated-replay-v1")
        )
    assert candidate["state"] == "VALIDATING"


def test_owner_approval_scope_and_nonce_replay_fail_closed(tmp_path):
    lifecycle = _lifecycle(tmp_path)
    candidate = _validated(lifecycle)
    auth = _owner_approval(lifecycle, candidate)
    bad = dict(auth)
    bad["isolated_root"] = str(tmp_path / "production")
    with pytest.raises(LifecycleError, match="scope"):
        lifecycle.approve(candidate, bad)
    lifecycle.approve(candidate, auth)
    assert candidate["state"] == "APPROVED_FOR_ISOLATED_LAB"
    with pytest.raises(LifecycleError, match="not awaiting"):
        lifecycle.approve(candidate, auth)
    lifecycle2 = _lifecycle(tmp_path)
    candidate2 = lifecycle2.create_candidate(_candidate())
    lifecycle2.transition(candidate2, "VALIDATING")
    lifecycle2.record_validation(
        candidate2, _sign(_replay(candidate2), REPLAY_TEST_KEY, "isolated-replay-v1")
    )
    lifecycle2.transition(candidate2, "AWAITING_APPROVAL")
    with pytest.raises(LifecycleError, match="replay"):
        lifecycle2.approve(candidate2, auth)


def test_owner_authorization_expires_and_cannot_be_used_to_activate(tmp_path):
    lifecycle = _lifecycle(tmp_path)
    candidate = _validated(lifecycle)
    auth = _owner_approval(lifecycle, candidate)
    auth["expires_at"] = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    with pytest.raises(LifecycleError, match="expired"):
        lifecycle.approve(candidate, auth)
    lifecycle.approve(candidate, _owner_approval(lifecycle, candidate))
    with pytest.raises(LifecycleError, match="scope"):
        lifecycle.stage(candidate, tmp_path / "lab", activate=True, runtime=_runtime())


def test_blocked_conflicting_and_embedded_sid_rejected(tmp_path):
    lifecycle = _lifecycle(tmp_path, existing_sids={9103999})
    with pytest.raises(LifecycleError, match="SID"):
        lifecycle.create_candidate(_candidate())
    with pytest.raises(LifecycleError, match="SID"):
        lifecycle.create_candidate(_candidate(sid=9102001))
    independent = _lifecycle(tmp_path / "other")
    candidate = _candidate()
    candidate["sid"] = 9104000  # The rule still contains sid:9103999.
    with pytest.raises(LifecycleError, match="Rule text"):
        independent.create_candidate(candidate)


def test_modified_rule_and_unsafe_lab_path_rejected(tmp_path):
    lifecycle = _lifecycle(tmp_path)
    candidate = _approved(lifecycle)
    with pytest.raises(LifecycleError, match="Unsafe"):
        lifecycle.stage(candidate, tmp_path / "outside")
    candidate["rule"] += " modified"
    with pytest.raises(LifecycleError, match="Rule text"):
        lifecycle.stage(candidate, tmp_path / "lab")


def test_activation_requires_verified_runtime_and_actual_active_check(tmp_path):
    lifecycle = _lifecycle(tmp_path)
    candidate = _approved(lifecycle, operation="activate")
    with pytest.raises(LifecycleError, match="runtime adapter"):
        lifecycle.stage(candidate, tmp_path / "lab", activate=True)
    with pytest.raises(LifecycleError, match="not verified"):
        lifecycle.stage(
            candidate, tmp_path / "lab", activate=True,
            runtime=_runtime(verified=False),
        )
    assert candidate["state"] == "ROLLED_BACK"
    assert not list((tmp_path / "lab").glob("*.rules"))


def test_synthetic_runtime_activation_and_verified_rollback(tmp_path):
    lifecycle = _lifecycle(tmp_path)
    candidate = _approved(lifecycle, operation="activate")
    runtime = _runtime()
    result = lifecycle.stage(candidate, tmp_path / "lab", activate=True, runtime=runtime)
    assert result["status"] == "active_in_isolated_lab"
    assert candidate["state"] == "ACTIVE_IN_ISOLATED_LAB"
    assert Path(result["path"]).is_file()
    with pytest.raises(LifecycleError, match="runtime rollback"):
        lifecycle.rollback(candidate)
    lifecycle.rollback(candidate, runtime=runtime)
    assert candidate["state"] == "ROLLED_BACK"
    assert not Path(result["path"]).exists()


def test_failed_runtime_rollback_is_not_reported_success(tmp_path):
    lifecycle = _lifecycle(tmp_path)
    candidate = _approved(lifecycle, operation="activate")
    runtime = _runtime(rollback_verified=False)
    lifecycle.stage(candidate, tmp_path / "lab", activate=True, runtime=_runtime())
    with pytest.raises(LifecycleError, match="could not be verified"):
        lifecycle.rollback(candidate, runtime=runtime)
    assert candidate["state"] == "FAILED"


def test_audit_chain_tampering_is_detected(tmp_path):
    lifecycle = _lifecycle(tmp_path)
    lifecycle.create_candidate(_candidate())
    path = tmp_path / "audit.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[0])
    record["event"] = "forged"
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    with pytest.raises(LifecycleError, match="Audit chain"):
        lifecycle.verify_audit()
    with pytest.raises(LifecycleError, match="Audit chain"):
        lifecycle.create_candidate(_candidate())


def test_concurrent_audit_writer_blocks_mutation(tmp_path):
    lifecycle = _lifecycle(tmp_path)
    lock = tmp_path / "audit.jsonl.lock"
    lock.write_text("other writer", encoding="utf-8")
    with pytest.raises(LifecycleError, match="Concurrent"):
        lifecycle.create_candidate(_candidate())


def test_isolated_root_must_be_explicit_and_nonproduction(tmp_path):
    with pytest.raises(LifecycleError, match="isolated-lab directory"):
        RuleLifecycle(tmp_path / "audit.jsonl", isolated_root=tmp_path / "production-rules")
    assert not (tmp_path / "production-rules").exists()

    with pytest.raises(LifecycleError, match="protected Suricata"):
        RuleLifecycle(tmp_path / "audit.jsonl", isolated_root=Path("/etc/suricata/isolated-lab"))
