import copy
import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest

from netids.g5_frozen_candidate import (
    FROZEN_CANDIDATE_SCHEMA,
    FrozenCandidateError,
    build_frozen_candidate,
    sign_frozen_replay_attestation,
    verify_frozen_candidate,
    verify_frozen_owner_authorization,
    verify_frozen_replay_attestation,
    verify_frozen_runtime_result,
)
from netids.lifecycle_ed25519 import generate_encrypted_keypair, sign_record
from netids.rule_lifecycle import RuleLifecycle


def _candidate():
    cases = [
        {"case": "A1", "label": "ATTACK", "run_id": "a1", "pcap_sha256": "a" * 64, "alerts": 8},
        {"case": "A2", "label": "ATTACK", "run_id": "a2", "pcap_sha256": "b" * 64, "alerts": 8},
        {"case": "A3", "label": "ATTACK", "run_id": "a3", "pcap_sha256": "c" * 64, "alerts": 8},
        {"case": "N1", "label": "NORMAL", "run_id": "n1", "pcap_sha256": "d" * 64, "alerts": 0},
        {"case": "N2", "label": "NORMAL", "run_id": "n2", "pcap_sha256": "e" * 64, "alerts": 0},
        {"case": "N3", "label": "NORMAL", "run_id": "n3", "pcap_sha256": "f" * 64, "alerts": 0},
    ]
    candidate = {
        "schema_version": FROZEN_CANDIDATE_SCHEMA,
        "candidate_family": "rst_response_v1",
        "sid": 9103005,
        "run_id": "g4-rst-dev-20261124T075112Z-9d0b815b",
        "rule_sha256": "1" * 64,
        "rule_file_sha256": "1" * 64,
        "rule_content_sha256": "2" * 64,
        "pcap_sha256": "3" * 64,
        "model_sha256": "4" * 64,
        "calibration_sha256": "5" * 64,
        "development_evidence_sha256": "6" * 64,
        "metadata_sha256": "7" * 64,
        "freeze_sha256": "8" * 64,
        "cohort_results_sha256": "9" * 64,
        "native_holdout_report_sha256": "a" * 64,
        "baseline_rules_sha256": "b" * 64,
        "baseline_comparison_sha256": "c" * 64,
        "source_commit": "d" * 40,
        "cohort_cases": cases,
        "approved": False,
        "deployable": False,
        "deployed": False,
    }
    rule = 'alert tcp 192.168.10.10 any -> 192.168.10.20 any (flags:R+; sid:9103005; rev:1;)'
    candidate["rule"] = rule
    candidate["rule_sha256"] = hashlib.sha256(rule.encode()).hexdigest()
    candidate["rule_content_sha256"] = candidate["rule_sha256"]
    candidate["rule_file_sha256"] = hashlib.sha256((rule + "\n").encode()).hexdigest()
    candidate["cohort_cases_sha256"] = hashlib.sha256(
        json.dumps(candidate["cohort_cases"], sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    identity = {
        key: candidate[key]
        for key in (
            "sid", "rule_file_sha256", "freeze_sha256",
            "cohort_results_sha256", "native_holdout_report_sha256",
            "baseline_rules_sha256", "baseline_comparison_sha256",
            "cohort_cases_sha256",
        )
    }
    candidate["candidate_id"] = hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return candidate


def _baseline(candidate):
    baseline = {
        "scope": "G5_OFFLINE_BASELINE_AUGMENTED_COMPARISON_ONLY",
        "sid": candidate["sid"],
        "candidate_rule_sha256": candidate["rule_file_sha256"],
        "baseline_rules_sha256": candidate["baseline_rules_sha256"],
        "augmented_rules_sha256": "d" * 64,
        "baseline_active_sid_count": 53249,
        "candidate_specific_comparison_pass": True,
        "all_other_sid_counts_equal": True,
        "production_unchanged": True,
        "runtime_activation_performed": False,
        "rollback_performed": False,
    }
    candidate["baseline_comparison_sha256"] = hashlib.sha256(
        json.dumps(baseline, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    candidate["baseline_comparison"] = baseline
    identity = {
        key: candidate[key]
        for key in (
            "sid", "rule_file_sha256", "freeze_sha256",
            "cohort_results_sha256", "native_holdout_report_sha256",
            "baseline_rules_sha256", "baseline_comparison_sha256",
            "cohort_cases_sha256",
        )
    }
    candidate["candidate_id"] = hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return baseline


def _runtime_evidence(candidate):
    return {
        "schema_version": "g5_frozen_rst_replay_attestation_v1",
        "candidate_id": candidate["candidate_id"],
        "run_id": candidate["run_id"],
        "sid": candidate["sid"],
        "rule_file_sha256": candidate["rule_file_sha256"],
        "rule_sha256": candidate["rule_sha256"],
        "freeze_sha256": candidate["freeze_sha256"],
        "cohort_results_sha256": candidate["cohort_results_sha256"],
        "baseline_rules_sha256": candidate["baseline_rules_sha256"],
        "cohort_cases": copy.deepcopy(candidate["cohort_cases"]),
        "pcap_sha256": candidate["pcap_sha256"],
        "model_sha256": candidate["model_sha256"],
        "calibration_sha256": candidate["calibration_sha256"],
        "experiment_id": "g5-frozen-rst-runtime-test",
        "threshold": 3,
        "syntax_authenticated": True,
        "candidate_loaded": True,
        "attack_replay_passed": True,
        "normal_replay_passed": True,
        "negative_control_passed": True,
        "normal_false_positive_count": 0,
        "negative_control_false_positive_count": 0,
        "production_unchanged": True,
        "approved": False,
        "deployed": False,
    }


def test_frozen_candidate_identity_binds_six_case_cohort_and_baseline():
    candidate = _candidate()
    result = verify_frozen_candidate(candidate, _baseline(candidate))
    assert result["candidate_id"] == candidate["candidate_id"]
    assert result["cohort_case_count"] == 6

    substituted = copy.deepcopy(candidate)
    substituted["baseline_rules_sha256"] = "e" * 64
    with pytest.raises(FrozenCandidateError, match="identity"):
        verify_frozen_candidate(substituted, _baseline(candidate))


def test_frozen_candidate_rejects_manifest_substitution_and_tampered_evidence():
    candidate = _candidate()
    baseline = _baseline(candidate)
    tampered = copy.deepcopy(baseline)
    tampered["baseline_rules_sha256"] = "e" * 64
    with pytest.raises(FrozenCandidateError, match="baseline"):
        verify_frozen_candidate(candidate, tampered)

    tampered = copy.deepcopy(candidate)
    tampered["cohort_cases"][0]["pcap_sha256"] = "0" * 64
    with pytest.raises(FrozenCandidateError, match="cohort"):
        verify_frozen_candidate(tampered, baseline)


def test_signed_frozen_replay_rejects_wrong_identity_and_invalid_signature():
    candidate = _candidate()
    private, public = generate_encrypted_keypair(b"replay-password")
    signed = sign_frozen_replay_attestation(
        candidate, _runtime_evidence(candidate), private, b"replay-password"
    )
    assert verify_frozen_replay_attestation(candidate, signed, public) is True

    wrong = copy.deepcopy(signed)
    wrong["candidate_id"] = "0" * 64
    assert verify_frozen_replay_attestation(candidate, wrong, public) is False
    assert verify_frozen_replay_attestation(candidate, signed, b"not-a-key") is False


def test_missing_or_tampered_owner_authorization_fails_closed():
    candidate = _candidate()
    replay_private, replay_public = generate_encrypted_keypair(b"replay-password")
    signed = sign_frozen_replay_attestation(
        candidate, _runtime_evidence(candidate), replay_private, b"replay-password"
    )
    owner_private, owner_public = generate_encrypted_keypair(b"owner-password")
    assert verify_frozen_owner_authorization(
        candidate, signed, {}, replay_public, owner_public
    ) is False
    tampered = dict(signed)
    tampered["candidate_id"] = "0" * 64
    assert verify_frozen_owner_authorization(
        candidate, signed, tampered, replay_public, owner_public
    ) is False


def test_runtime_result_requires_rollback_cleanup_and_unchanged_production():
    candidate = _candidate()
    replay = _runtime_evidence(candidate)
    result = {
        "schema_version": "g5_frozen_runtime_acceptance_v1",
        "candidate_id": candidate["candidate_id"],
        "sid": candidate["sid"],
        "rule_file_sha256": candidate["rule_file_sha256"],
        "replay_evidence_sha256": hashlib.sha256(
            json.dumps(replay, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "owner_authorization_sha256": "2" * 64,
        "candidate_loaded": True,
        "attack_replay_passed": True,
        "normal_replay_passed": True,
        "negative_control_passed": True,
        "rollback_verified": True,
        "post_rollback_verified": True,
        "child_process_cleanup_verified": True,
        "production_unchanged": True,
        "outcome": "VERIFIED_ISOLATED_ACTIVATION_AND_ROLLBACK",
        "approved": False,
        "deployed": False,
    }
    assert verify_frozen_runtime_result(candidate, replay, result) is True

    for field, value in (
        ("rollback_verified", False),
        ("child_process_cleanup_verified", False),
        ("production_unchanged", False),
    ):
        broken = dict(result)
        broken[field] = value
        with pytest.raises(FrozenCandidateError, match="runtime"):
            verify_frozen_runtime_result(candidate, replay, broken)


def test_frozen_schema_uses_existing_lifecycle_with_versioned_domains(tmp_path):
    candidate = _candidate()
    _baseline(candidate)
    replay_private, replay_public = generate_encrypted_keypair(b"replay-password")
    replay = sign_frozen_replay_attestation(
        candidate, _runtime_evidence(candidate), replay_private, b"replay-password"
    )
    owner_private, owner_public = generate_encrypted_keypair(b"owner-password")
    root = tmp_path / "isolated-lab"
    now_dt = datetime.now(timezone.utc)
    now = now_dt.isoformat()
    owner = sign_record({
        "schema_version": "g5_frozen_owner_authorization_v1",
        "candidate_id": candidate["candidate_id"],
        "run_id": candidate["run_id"],
        "sid": candidate["sid"],
        "rule_sha256": candidate["rule_sha256"],
        "environment": "isolated-lab",
        "operation": "activate",
        "isolated_root": str(root.resolve()),
        "approver_identity": "owner",
        "nonce": "1" * 32,
        "approved_at": now,
        "expires_at": (now_dt + timedelta(minutes=15)).isoformat(),
    }, owner_private, b"owner-password", domain="g5-frozen-owner-v1")
    lifecycle = RuleLifecycle(
        tmp_path / "audit.jsonl", isolated_root=root,
        replay_verification_key=replay_public,
        owner_verification_key=owner_public,
        replay_domain="g5-frozen-replay-v1",
        owner_domain="g5-frozen-owner-v1",
    )
    proposed = lifecycle.create_candidate(candidate)
    lifecycle.transition(proposed, "VALIDATING")
    lifecycle.record_validation(proposed, replay)
    lifecycle.transition(proposed, "AWAITING_APPROVAL")
    lifecycle.approve(proposed, owner)
    assert proposed["state"] == "APPROVED_FOR_ISOLATED_LAB"
