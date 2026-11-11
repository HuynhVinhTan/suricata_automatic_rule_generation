import hashlib
import json

import pytest

from netids.rule_lifecycle import LifecycleError, RuleLifecycle


def _candidate(tmp_path):
    rule = 'alert tcp any any -> 192.0.2.10 any (msg:"test"; sid:9103999; rev:1;)'
    return {
        "run_id": "run-001",
        "pcap_sha256": "a" * 64,
        "model_sha256": "b" * 64,
        "calibration_sha256": "c" * 64,
        "sid": 9103999,
        "rule": rule,
        "rule_sha256": hashlib.sha256(rule.encode()).hexdigest(),
        "approved": False,
        "deployable": False,
        "deployed": False,
    }


def test_lifecycle_requires_explicit_approval_and_audits_transitions(tmp_path):
    lifecycle = RuleLifecycle(tmp_path / "audit.jsonl")
    candidate = lifecycle.create_candidate(_candidate(tmp_path))

    assert candidate["state"] == "PROPOSED"
    with pytest.raises(LifecycleError, match="approval"):
        lifecycle.stage(candidate, tmp_path / "lab-rules")

    lifecycle.transition(candidate, "VALIDATING")
    lifecycle.transition(candidate, "VALIDATED_FOR_REVIEW")
    lifecycle.transition(candidate, "AWAITING_APPROVAL")
    lifecycle.approve(candidate, approver="owner", approved_at="2026-11-12T00:00:00Z")
    assert candidate["state"] == "APPROVED_FOR_ISOLATED_LAB"
    assert lifecycle.stage(candidate, tmp_path / "lab-rules")["status"] == "dry_run"
    assert len((tmp_path / "audit.jsonl").read_text().splitlines()) >= 5


def test_lifecycle_rejects_modified_rule_and_unsafe_path(tmp_path):
    lifecycle = RuleLifecycle(tmp_path / "audit.jsonl")
    candidate = lifecycle.create_candidate(_candidate(tmp_path))
    lifecycle.transition(candidate, "VALIDATING")
    lifecycle.transition(candidate, "VALIDATED_FOR_REVIEW")
    lifecycle.transition(candidate, "AWAITING_APPROVAL")
    lifecycle.approve(candidate, approver="owner", approved_at="2026-11-12T00:00:00Z")
    candidate["rule"] += " modified"
    with pytest.raises(LifecycleError, match="hash"):
        lifecycle.stage(candidate, tmp_path / "lab-rules")
