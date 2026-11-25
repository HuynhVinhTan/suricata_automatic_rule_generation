import copy
import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest

from netids import key_pins
from netids.g5_frozen_candidate import (
    FROZEN_CANDIDATE_SCHEMA,
    FrozenCandidateError,
    build_frozen_candidate,
    build_frozen_owner_authorization,
    prepare_frozen_replay_evidence,
    sign_frozen_replay_attestation,
    verify_frozen_candidate,
    verify_frozen_owner_authorization,
    verify_frozen_replay_attestation,
    verify_frozen_runtime_result,
)
from netids.lifecycle_ed25519 import generate_encrypted_keypair, private_key_matches_public, public_key_fingerprint, sign_record
from netids.latency import LatencyTrace
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
        "native_holdout_report_sha256": candidate["native_holdout_report_sha256"],
        "cohort_cases_sha256": candidate["cohort_cases_sha256"],
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
        "probe_plan": [
            {
                "case": case["case"],
                "label": case["label"],
                "scenario": "attack" if case["label"] == "ATTACK" else ("normal" if case["case"] == "N1" else "negative_control"),
                "pcap_sha256": case["pcap_sha256"],
                "expected_alert": case["label"] == "ATTACK",
            }
            for case in candidate["cohort_cases"]
        ],
        "production_unchanged": True,
        "evidence_provenance": {
            "native_holdout_report_sha256": candidate["native_holdout_report_sha256"],
            "cohort_results_sha256": candidate["cohort_results_sha256"],
            "syntax_log_sha256": "e" * 64,
            "production_pid_state_yaml_unchanged": True,
            "capture_and_handoff_complete": True,
        },
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


def test_signed_frozen_replay_rejects_wrong_identity_and_invalid_signature(monkeypatch):
    candidate = _candidate()
    private, public = generate_encrypted_keypair(b"replay-password")
    signed = sign_frozen_replay_attestation(
        candidate, _runtime_evidence(candidate), private, b"replay-password"
    )
    monkeypatch.setattr(
        key_pins,
        "PINNED_G5_FROZEN_REPLAY_ED25519_SHA256",
        public_key_fingerprint(public),
    )
    assert verify_frozen_replay_attestation(candidate, signed, public) is True

    wrong = copy.deepcopy(signed)
    wrong["candidate_id"] = "0" * 64
    assert verify_frozen_replay_attestation(candidate, wrong, public) is False
    assert verify_frozen_replay_attestation(candidate, signed, b"not-a-key") is False


def test_frozen_replay_verification_requires_candidate_specific_anchor(monkeypatch):
    candidate = _candidate()
    replay_private, replay_public = generate_encrypted_keypair(b"replay-password")
    signed = sign_frozen_replay_attestation(
        candidate, _runtime_evidence(candidate), replay_private, b"replay-password"
    )
    monkeypatch.setattr(
        key_pins,
        "PINNED_G5_FROZEN_REPLAY_ED25519_SHA256",
        public_key_fingerprint(replay_public),
    )
    assert verify_frozen_replay_attestation(candidate, signed, replay_public) is True
    monkeypatch.setattr(
        key_pins,
        "PINNED_G5_FROZEN_REPLAY_ED25519_SHA256",
        key_pins.PINNED_REPLAY_ED25519_SHA256,
    )
    assert verify_frozen_replay_attestation(candidate, signed, replay_public) is False


def test_signed_frozen_replay_requires_lifecycle_provenance_and_exact_probe_plan(monkeypatch):
    candidate = _candidate()
    private, public = generate_encrypted_keypair(b"replay-password")
    evidence = _runtime_evidence(candidate)
    missing_run = dict(evidence)
    missing_run.pop("run_id")
    with pytest.raises(FrozenCandidateError, match="run_id"):
        sign_frozen_replay_attestation(candidate, missing_run, private, b"replay-password")

    wrong_rule = dict(evidence)
    wrong_rule["rule_sha256"] = "0" * 64
    with pytest.raises(FrozenCandidateError, match="rule_sha256"):
        sign_frozen_replay_attestation(candidate, wrong_rule, private, b"replay-password")

    duplicate_probe = copy.deepcopy(evidence)
    duplicate_probe["probe_plan"][1]["case"] = duplicate_probe["probe_plan"][0]["case"]
    with pytest.raises(FrozenCandidateError, match="probe"):
        sign_frozen_replay_attestation(candidate, duplicate_probe, private, b"replay-password")

    signed = sign_frozen_replay_attestation(candidate, evidence, private, b"replay-password")
    monkeypatch.setattr(
        key_pins,
        "PINNED_G5_FROZEN_REPLAY_ED25519_SHA256",
        public_key_fingerprint(public),
    )
    assert verify_frozen_replay_attestation(candidate, signed, public) is True


def test_replay_evidence_preparation_derives_only_verified_native_fields():
    candidate = _candidate()
    report = {
        "candidate_holdout_pass": True,
        "approved": False,
        "deployed": False,
        "production_pid_state_yaml_unchanged": True,
        "syntax_log_sha256": "e" * 64,
        "evidence_dir": "/verified/native-holdout",
        "cases": [
            dict(case, label=case["label"], alerts=8 if case["label"] == "ATTACK" else 0)
            for case in candidate["cohort_cases"]
        ],
    }
    cohort = {"capture_and_handoff_complete": True, "approved": False, "deployed": False}
    metadata = {
        "rule_sha256": candidate["rule_sha256"],
        "normal_cal_max_rst": 2,
        "normal_calibration_provenance": {"final_holdout_used": False},
    }
    evidence = prepare_frozen_replay_evidence(candidate, report, cohort, metadata)
    assert evidence["threshold"] == 3
    assert {probe["case"] for probe in evidence["probe_plan"]} == {case["case"] for case in candidate["cohort_cases"]}
    assert evidence["negative_control_passed"] is True
    tampered = copy.deepcopy(report)
    tampered["cases"][0]["label"] = "NORMAL"
    with pytest.raises(FrozenCandidateError, match="label"):
        prepare_frozen_replay_evidence(candidate, tampered, cohort, metadata)


def test_missing_or_tampered_owner_authorization_fails_closed():
    candidate = _candidate()
    replay_private, replay_public = generate_encrypted_keypair(b"replay-password")
    signed = sign_frozen_replay_attestation(
        candidate, _runtime_evidence(candidate), replay_private, b"replay-password"
    )
    owner_private, owner_public = generate_encrypted_keypair(b"owner-password")
    _, runtime_public = generate_encrypted_keypair(b"runtime-password")
    assert verify_frozen_owner_authorization(
        candidate, signed, {}, replay_public, owner_public, runtime_public
    ) is False
    tampered = dict(signed)
    tampered["candidate_id"] = "0" * 64
    assert verify_frozen_owner_authorization(
        candidate, signed, tampered, replay_public, owner_public, runtime_public
    ) is False


def test_runtime_result_requires_rollback_cleanup_and_unchanged_production():
    candidate = _candidate()
    replay = _runtime_evidence(candidate)
    runtime_private, runtime_public = generate_encrypted_keypair(b"runtime-password")
    _, wrong_public = generate_encrypted_keypair(b"wrong-password")
    probe_results = []
    for phase in ("active", "rollback"):
        for probe in replay["probe_plan"]:
            probe_results.append({
                "case": probe["case"], "label": probe["label"],
                "scenario": probe["scenario"], "phase": phase,
                "pcap_sha256": probe["pcap_sha256"],
                "expected_alert": probe["expected_alert"] if phase == "active" else False,
                "candidate_alerts": 1 if phase == "active" and probe["expected_alert"] else 0,
            })
    result = {
        "schema_version": "g5_frozen_runtime_acceptance_v1",
        "candidate_id": candidate["candidate_id"],
        "sid": candidate["sid"],
        "rule_file_sha256": candidate["rule_file_sha256"],
        "replay_evidence_sha256": hashlib.sha256(
            json.dumps(replay, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "owner_authorization_sha256": "2" * 64,
        "elapsed_seconds": 1,
        "max_runtime_seconds": 300,
        "deadline_enforced": True,
        "candidate_loaded": True,
        "attack_replay_passed": True,
        "normal_replay_passed": True,
        "negative_control_passed": True,
        "rollback_verified": True,
        "post_rollback_verified": True,
        "child_process_cleanup_verified": True,
        "production_unchanged": True,
        "probe_results": probe_results,
        "outcome": "VERIFIED_ISOLATED_ACTIVATION_AND_ROLLBACK",
        "approved": False,
        "deployed": False,
    }
    signed = sign_record(result, runtime_private, b"runtime-password", domain="g5-frozen-runtime-v1")
    assert verify_frozen_runtime_result(candidate, replay, signed, runtime_public) is True
    assert private_key_matches_public(runtime_private, b"runtime-password", runtime_public) is True
    assert private_key_matches_public(runtime_private, b"runtime-password", wrong_public) is False
    with pytest.raises(FrozenCandidateError, match="signature"):
        verify_frozen_runtime_result(candidate, replay, signed, wrong_public)

    for field, value in (
        ("rollback_verified", False),
        ("child_process_cleanup_verified", False),
        ("production_unchanged", False),
    ):
        broken = dict(signed)
        broken[field] = value
        with pytest.raises(FrozenCandidateError, match="runtime"):
            verify_frozen_runtime_result(candidate, replay, broken, runtime_public)


def test_runtime_result_latency_trace_is_bound_to_candidate_run():
    candidate = _candidate()
    replay = _runtime_evidence(candidate)
    runtime_private, runtime_public = generate_encrypted_keypair(b"runtime-password")
    probe_results = []
    for phase in ("active", "rollback"):
        for probe in replay["probe_plan"]:
            probe_results.append({
                "case": probe["case"], "label": probe["label"],
                "scenario": probe["scenario"], "phase": phase,
                "pcap_sha256": probe["pcap_sha256"],
                "expected_alert": probe["expected_alert"] if phase == "active" else False,
                "candidate_alerts": 1 if phase == "active" and probe["expected_alert"] else 0,
            })
    trace = LatencyTrace(run_id=candidate["run_id"], host="vm1", clock_sync={"status": "same_host_monotonic", "offset_ms": 0.0})
    with trace.stage("isolated_runtime_activation", component="runtime"):
        pass
    result = {
        "schema_version": "g5_frozen_runtime_acceptance_v1",
        "candidate_id": candidate["candidate_id"], "sid": candidate["sid"],
        "rule_file_sha256": candidate["rule_file_sha256"],
        "replay_evidence_sha256": hashlib.sha256(json.dumps(replay, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        "owner_authorization_sha256": "2" * 64, "elapsed_seconds": 1,
        "max_runtime_seconds": 300, "deadline_enforced": True,
        "candidate_loaded": True, "attack_replay_passed": True,
        "normal_replay_passed": True, "negative_control_passed": True,
        "rollback_verified": True, "post_rollback_verified": True,
        "child_process_cleanup_verified": True, "production_unchanged": True,
        "probe_results": probe_results,
        "outcome": "VERIFIED_ISOLATED_ACTIVATION_AND_ROLLBACK",
        "approved": False, "deployed": False,
        "latency_trace_binding": "signed_runtime_result_field",
        "latency_trace": trace.as_dict(),
    }
    signed = sign_record(result, runtime_private, b"runtime-password", domain="g5-frozen-runtime-v1")
    assert verify_frozen_runtime_result(candidate, replay, signed, runtime_public) is True
    broken_record = {
        key: value for key, value in signed.items()
        if not key.startswith("attestation_")
    }
    broken_record["latency_trace"] = LatencyTrace(run_id="different-run").as_dict()
    broken = sign_record(broken_record, runtime_private, b"runtime-password", domain="g5-frozen-runtime-v1")
    with pytest.raises(FrozenCandidateError, match="latency"):
        verify_frozen_runtime_result(candidate, replay, broken, runtime_public)


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


def test_frozen_bridge_owner_contract_reaches_real_lifecycle(tmp_path, monkeypatch):
    candidate = _candidate()
    _baseline(candidate)
    replay_private, replay_public = generate_encrypted_keypair(b"replay-password")
    replay = sign_frozen_replay_attestation(
        candidate, _runtime_evidence(candidate), replay_private, b"replay-password"
    )
    owner_private, owner_public = generate_encrypted_keypair(b"owner-password")
    runtime_private, runtime_public = generate_encrypted_keypair(b"runtime-password")
    monkeypatch.setattr(
        key_pins,
        "PINNED_G5_FROZEN_REPLAY_ED25519_SHA256",
        public_key_fingerprint(replay_public),
    )
    monkeypatch.setattr(
        key_pins,
        "PINNED_OWNER_ED25519_SHA256",
        public_key_fingerprint(owner_public),
    )
    owner = build_frozen_owner_authorization(
        candidate, replay, replay_public_pem=replay_public,
        owner_private_pem=owner_private, owner_private_password=b"owner-password",
        owner_public_pem=owner_public, runtime_public_pem=runtime_public,
        approver_identity="owner", isolated_root=str((tmp_path / "isolated-lab").resolve()),
        runtime_id="suricata-vm1:isolated-lifecycle-9103005:lo",
        target_vm="suricata-vm1", interface="lo", nonce="1" * 32,
    )
    assert owner["rule_sha256"] == candidate["rule_sha256"]
    assert verify_frozen_owner_authorization(
        candidate, replay, owner, replay_public, owner_public, runtime_public
    ) is True
    assert verify_frozen_owner_authorization(
        candidate, replay, owner, replay_public, owner_public, replay_public
    ) is False
    assert verify_frozen_owner_authorization(
        candidate, replay, owner, replay_public, owner_public, runtime_public,
        now=datetime.now(timezone.utc) + timedelta(hours=1),
    ) is False
    lifecycle = RuleLifecycle(
        tmp_path / "audit.jsonl", isolated_root=tmp_path / "isolated-lab",
        replay_verification_key=replay_public, owner_verification_key=owner_public,
        replay_domain="g5-frozen-replay-v1", owner_domain="g5-frozen-owner-v1",
    )
    proposed = lifecycle.create_candidate(candidate)
    lifecycle.transition(proposed, "VALIDATING")
    lifecycle.record_validation(proposed, replay)
    lifecycle.transition(proposed, "AWAITING_APPROVAL")
    lifecycle.approve(proposed, owner)
    assert proposed["state"] == "APPROVED_FOR_ISOLATED_LAB"
