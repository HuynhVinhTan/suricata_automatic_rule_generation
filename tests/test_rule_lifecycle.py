import hashlib
import pytest

from netids.rule_lifecycle import LifecycleError, RuleLifecycle


def _candidate(tmp_path, sid=9103999):
    rule = f'alert tcp any any -> 192.0.2.10 any (msg:"test"; sid:{sid}; rev:1;)'
    return {
        "run_id": "run-001",
        "pcap_sha256": "a" * 64,
        "model_sha256": "b" * 64,
        "calibration_sha256": "c" * 64,
        "sid": sid,
        "rule": rule,
        "rule_sha256": hashlib.sha256(rule.encode()).hexdigest(),
        "approved": False,
        "deployable": False,
        "deployed": False,
    }


def test_lifecycle_requires_explicit_approval_and_audits_transitions(tmp_path):
    lifecycle = RuleLifecycle(tmp_path / "audit.jsonl", isolated_root=tmp_path / "lab")
    candidate = lifecycle.create_candidate(_candidate(tmp_path))

    assert candidate["state"] == "PROPOSED"
    with pytest.raises(LifecycleError, match="approval"):
        lifecycle.stage(candidate, tmp_path / "lab-rules")

    lifecycle.transition(candidate, "VALIDATING")
    evidence = {
        "syntax_authenticated": True,
        "attack_replay_passed": True,
        "normal_replay_passed": True,
        "candidate_id": candidate["candidate_id"],
        "run_id": candidate["run_id"],
        "experiment_id": "exp-1",
        "sid": candidate["sid"],
        "rule_sha256": candidate["rule_sha256"],
        "pcap_sha256": candidate["pcap_sha256"],
        "model_sha256": candidate["model_sha256"],
        "calibration_sha256": candidate["calibration_sha256"],
        "threshold": 3,
    }
    lifecycle.record_validation(candidate, evidence)
    lifecycle.transition(candidate, "AWAITING_APPROVAL")
    authorization = {
        "candidate_id": candidate["candidate_id"], "run_id": candidate["run_id"],
        "sid": candidate["sid"], "rule_sha256": candidate["rule_sha256"],
        "environment": "isolated-lab", "operation": "stage",
        "approver_identity": "owner@example.invalid",
        "approved_at": "2026-11-12T00:00:00Z", "expires_at": "2026-11-13T00:00:00Z",
    }
    lifecycle.approve(candidate, authorization, authorization_verifier=lambda value: value == authorization)
    assert candidate["state"] == "APPROVED_FOR_ISOLATED_LAB"
    assert lifecycle.stage(candidate, tmp_path / "lab")["status"] == "dry_run"
    assert len((tmp_path / "audit.jsonl").read_text().splitlines()) >= 5


def test_lifecycle_rejects_modified_rule_and_unsafe_path(tmp_path):
    lifecycle = RuleLifecycle(tmp_path / "audit.jsonl", isolated_root=tmp_path / "lab")
    candidate = lifecycle.create_candidate(_candidate(tmp_path))
    lifecycle.transition(candidate, "VALIDATING")
    lifecycle.record_validation(candidate, {
        "syntax_authenticated": True, "attack_replay_passed": True,
        "normal_replay_passed": True, "candidate_id": candidate["candidate_id"],
        "run_id": candidate["run_id"], "experiment_id": "exp-1", "sid": candidate["sid"],
        "rule_sha256": candidate["rule_sha256"], "pcap_sha256": candidate["pcap_sha256"],
        "model_sha256": candidate["model_sha256"], "calibration_sha256": candidate["calibration_sha256"], "threshold": 3,
    })
    lifecycle.transition(candidate, "AWAITING_APPROVAL")
    auth = {"candidate_id": candidate["candidate_id"], "run_id": candidate["run_id"], "sid": candidate["sid"], "rule_sha256": candidate["rule_sha256"], "environment": "isolated-lab", "operation": "stage", "approver_identity": "owner@example.invalid", "approved_at": "2026-11-12T00:00:00Z", "expires_at": "2026-11-13T00:00:00Z"}
    lifecycle.approve(candidate, auth, authorization_verifier=lambda value: value == auth)
    candidate["rule"] += " modified"
    with pytest.raises(LifecycleError, match="hash"):
        lifecycle.stage(candidate, tmp_path / "lab-rules")


def test_lifecycle_rejects_blocked_and_conflicting_sids(tmp_path):
    lifecycle = RuleLifecycle(tmp_path / "audit.jsonl", isolated_root=tmp_path / "lab", existing_sids={9103999})
    with pytest.raises(LifecycleError, match="SID"):
        lifecycle.create_candidate(_candidate(tmp_path))
    with pytest.raises(LifecycleError, match="rejected"):
        lifecycle.create_candidate(_candidate(tmp_path, sid=9102001))


def test_lifecycle_rejects_spoofed_or_expired_authorization(tmp_path):
    lifecycle = RuleLifecycle(tmp_path / "audit.jsonl", isolated_root=tmp_path / "lab")
    candidate = lifecycle.create_candidate(_candidate(tmp_path))
    lifecycle.transition(candidate, "VALIDATING")
    evidence = {"syntax_authenticated": True, "attack_replay_passed": True, "normal_replay_passed": True,
                "candidate_id": candidate["candidate_id"], "run_id": candidate["run_id"], "experiment_id": "exp-1",
                "sid": candidate["sid"], "rule_sha256": candidate["rule_sha256"], "pcap_sha256": candidate["pcap_sha256"],
                "model_sha256": candidate["model_sha256"], "calibration_sha256": candidate["calibration_sha256"], "threshold": 3}
    lifecycle.record_validation(candidate, evidence)
    lifecycle.transition(candidate, "AWAITING_APPROVAL")
    authorization = {"candidate_id": candidate["candidate_id"], "run_id": candidate["run_id"], "sid": candidate["sid"],
                     "rule_sha256": "0" * 64, "environment": "isolated-lab", "operation": "stage",
                     "approver_identity": "owner@example.invalid", "approved_at": "2026-11-12T00:00:00Z",
                     "expires_at": "2026-11-13T00:00:00Z"}
    with pytest.raises(LifecycleError, match="provenance"):
        lifecycle.approve(candidate, authorization, authorization_verifier=lambda _: True)
