"""Signed bridge for the frozen six-case SID9103005 G5 workflow.

The bridge is deliberately separate from ``candidate_record_v1``.  It binds
the existing freeze/cohort/native evidence and baseline comparison directly;
it never invents worker review artifacts or changes the historical lifecycle
contract.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone

from netids.lifecycle_ed25519 import (
    private_key_matches_public,
    public_key_fingerprint,
    sign_record,
    verify_record,
)


FROZEN_CANDIDATE_SCHEMA = "g5_frozen_rst_candidate_v1"
FROZEN_REPLAY_SCHEMA = "g5_frozen_rst_replay_attestation_v1"
FROZEN_OWNER_SCHEMA = "g5_frozen_owner_authorization_v1"
FROZEN_RUNTIME_SCHEMA = "g5_frozen_runtime_acceptance_v1"
FROZEN_REPLAY_DOMAIN = "g5-frozen-replay-v1"
FROZEN_OWNER_DOMAIN = "g5-frozen-owner-v1"
FROZEN_RUNTIME_DOMAIN = "g5-frozen-runtime-v1"
SID = 9103005
_SHA = re.compile(r"^[0-9a-f]{64}$")


class FrozenCandidateError(ValueError):
    """A frozen-candidate identity, signature, or runtime gate failed."""


def _digest(value):
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")).hexdigest()


def _sha(value, field):
    if not isinstance(value, str) or not _SHA.fullmatch(value.lower()):
        raise FrozenCandidateError(f"invalid {field}")
    return value.lower()


def _require(condition, message):
    if not condition:
        raise FrozenCandidateError(message)


def _verify_cases(candidate):
    cases = candidate.get("cohort_cases")
    _require(isinstance(cases, list) and len(cases) == 6, "frozen cohort must contain six cases")
    names = set()
    runs = set()
    pcaps = set()
    for case in cases:
        _require(isinstance(case, dict), "invalid frozen cohort case")
        name = case.get("case")
        run_id = case.get("run_id")
        pcap = _sha(case.get("pcap_sha256"), "cohort PCAP SHA256")
        _require(isinstance(name, str) and name not in names, "duplicate frozen cohort case")
        _require(isinstance(run_id, str) and run_id not in runs, "duplicate frozen cohort run")
        _require(pcap not in pcaps, "duplicate frozen cohort PCAP")
        _require(case.get("label") in {"ATTACK", "NORMAL"}, "invalid frozen cohort label")
        _require(type(case.get("alerts")) is int and case["alerts"] >= 0, "invalid cohort alert count")
        names.add(name)
        runs.add(run_id)
        pcaps.add(pcap)
    _require(sum(case["label"] == "ATTACK" for case in cases) == 3, "frozen cohort needs three Attack cases")
    _require(sum(case["label"] == "NORMAL" for case in cases) == 3, "frozen cohort needs three Normal cases")
    _require(names == {"A1", "A2", "A3", "N1", "N2", "N3"}, "frozen cohort case set mismatch")
    return cases


def _scenario_for_case(case):
    if case["label"] == "ATTACK":
        return "attack"
    return "normal" if case["case"] == "N1" else "negative_control"


def _verify_probe_plan(candidate, probe_plan):
    _require(isinstance(probe_plan, list) and len(probe_plan) == 6, "probe plan must contain six cases")
    expected = {case["case"]: case for case in candidate["cohort_cases"]}
    seen = set()
    for probe in probe_plan:
        _require(isinstance(probe, dict), "invalid probe plan case")
        name = probe.get("case")
        _require(name in expected and name not in seen, "probe plan case substitution or duplicate")
        case = expected[name]
        _require(probe.get("label") == case["label"], "probe plan label mismatch")
        _require(probe.get("pcap_sha256") == case["pcap_sha256"], "probe plan PCAP mismatch")
        _require(probe.get("scenario") == _scenario_for_case(case), "probe plan scenario mismatch")
        _require(probe.get("expected_alert") is (case["label"] == "ATTACK"), "probe plan alert expectation mismatch")
        seen.add(name)
    _require(seen == set(expected), "probe plan does not cover exact frozen cohort")


def _verify_candidate_shape(candidate):
    _require(isinstance(candidate, dict), "frozen candidate must be an object")
    _require(candidate.get("schema_version") == FROZEN_CANDIDATE_SCHEMA, "unsupported frozen candidate schema")
    _require(candidate.get("candidate_family") == "rst_response_v1", "frozen candidate family mismatch")
    _require(candidate.get("sid") == SID, "frozen candidate SID mismatch")
    _require(all(candidate.get(flag) is False for flag in ("approved", "deployable", "deployed")), "frozen candidate must remain review-only")
    for field in (
        "rule_sha256", "rule_file_sha256", "rule_content_sha256", "pcap_sha256",
        "model_sha256", "calibration_sha256", "development_evidence_sha256",
        "metadata_sha256", "freeze_sha256", "cohort_results_sha256",
        "native_holdout_report_sha256", "baseline_rules_sha256",
        "baseline_comparison_sha256", "cohort_cases_sha256",
    ):
        _sha(candidate.get(field), field)
    rule = candidate.get("rule")
    _require(isinstance(rule, str) and "\n" not in rule and "\r" not in rule, "frozen rule text is invalid")
    _require(hashlib.sha256(rule.encode()).hexdigest() == candidate["rule_sha256"], "frozen rule content hash mismatch")
    _verify_cases(candidate)
    _require(_digest(candidate["cohort_cases"]) == candidate["cohort_cases_sha256"], "frozen cohort evidence hash mismatch")

    identity = {
        key: candidate[key]
        for key in (
            "sid", "rule_file_sha256", "freeze_sha256", "cohort_results_sha256",
            "native_holdout_report_sha256", "baseline_rules_sha256",
            "baseline_comparison_sha256", "cohort_cases_sha256",
        )
    }
    expected_id = _digest(identity)
    _require(candidate.get("candidate_id") == expected_id, "frozen candidate identity mismatch")


def build_frozen_candidate(verification, baseline_comparison, *, baseline_comparison_sha256=None):
    """Create a new bridge envelope from verified evidence, without artifacts."""
    _require(verification.get("verified") is True, "frozen evidence is not verified")
    _require(verification.get("approved") is False and verification.get("deployed") is False, "frozen evidence is not review-only")
    _require(verification.get("sid") == SID, "frozen evidence SID mismatch")
    _require(verification.get("bounded_laboratory_signature") is True, "bounded signature marker is missing")
    _require(verification.get("hybrid_equivalent") is False, "RST signature cannot claim Hybrid equivalence")
    _require(isinstance(baseline_comparison, dict), "baseline comparison is required")
    _require(baseline_comparison.get("candidate_specific_comparison_pass") is True, "baseline comparison did not pass")
    _require(baseline_comparison.get("all_other_sid_counts_equal") is True, "baseline comparison changed another SID")
    _require(baseline_comparison.get("production_unchanged") is True, "baseline comparison changed production")
    _require(baseline_comparison.get("runtime_activation_performed") is False, "baseline comparison performed activation")
    _require(baseline_comparison.get("rollback_performed") is False, "baseline comparison performed rollback")
    comparison_sha = baseline_comparison_sha256 or _digest(baseline_comparison)
    _sha(comparison_sha, "baseline comparison SHA256")
    metadata = verification.get("metadata") or {}
    development = verification.get("development") or {}
    baseline_rules_sha256 = baseline_comparison.get("baseline_rules_sha256")
    if baseline_rules_sha256 is None:
        baseline_rules_sha256 = (
            baseline_comparison.get("baseline_preflight", {})
            .get("production", {})
            .get("rules_sha256")
        )
    candidate = {
        "schema_version": FROZEN_CANDIDATE_SCHEMA,
        "candidate_family": "rst_response_v1",
        "candidate_id": None,
        "sid": SID,
        "run_id": metadata.get("run_id"),
        "rule": verification.get("rule"),
        "rule_sha256": verification["rule_content_sha256"],
        "rule_file_sha256": verification["rule_file_sha256"],
        "rule_content_sha256": verification["rule_content_sha256"],
        "pcap_sha256": metadata.get("pcap_sha256"),
        "model_sha256": metadata.get("model_sha256"),
        "calibration_sha256": development.get("calibration_sha256"),
        "development_evidence_sha256": verification.get("development_evidence_sha256"),
        "metadata_sha256": verification.get("metadata_sha256"),
        "freeze_sha256": verification.get("freeze_sha256"),
        "cohort_results_sha256": verification.get("cohort_results_sha256"),
        "native_holdout_report_sha256": verification.get("native_holdout_report_sha256"),
        "cohort_cases_sha256": _digest(verification.get("cases")),
        "baseline_rules_sha256": baseline_rules_sha256,
        "baseline_comparison_sha256": comparison_sha,
        "source_commit": verification.get("source_commit"),
        "cohort_cases": verification.get("cases"),
        "baseline_comparison": dict(baseline_comparison),
        "approved": False,
        "deployable": False,
        "deployed": False,
    }
    identity = {
        key: candidate[key]
        for key in (
            "sid", "rule_file_sha256", "freeze_sha256", "cohort_results_sha256",
            "native_holdout_report_sha256", "baseline_rules_sha256",
            "baseline_comparison_sha256", "cohort_cases_sha256",
        )
    }
    candidate["candidate_id"] = _digest(identity)
    _verify_candidate_shape(candidate)
    return candidate


def verify_frozen_candidate(candidate, baseline_comparison=None):
    _verify_candidate_shape(candidate)
    if baseline_comparison is not None:
        _require(_digest(baseline_comparison) == candidate["baseline_comparison_sha256"], "baseline comparison evidence hash mismatch")
        _require(candidate.get("baseline_comparison") == baseline_comparison, "baseline comparison evidence substitution")
    return {
        "candidate_id": candidate["candidate_id"],
        "cohort_case_count": len(candidate["cohort_cases"]),
        "sid": SID,
        "approved": False,
        "deployed": False,
    }


def _verify_replay_shape(candidate, replay):
    _require(isinstance(replay, dict), "replay attestation must be an object")
    _require(replay.get("schema_version") == FROZEN_REPLAY_SCHEMA, "unsupported frozen replay schema")
    for field in ("candidate_id", "run_id", "sid", "rule_sha256", "rule_file_sha256", "freeze_sha256", "cohort_results_sha256", "baseline_rules_sha256", "native_holdout_report_sha256", "cohort_cases_sha256"):
        _require(replay.get(field) == candidate.get(field), f"frozen replay {field} mismatch")
    for field in ("pcap_sha256", "model_sha256", "calibration_sha256"):
        _require(replay.get(field) == candidate.get(field), f"frozen replay {field} mismatch")
    _require(isinstance(replay.get("experiment_id"), str) and replay["experiment_id"].strip(), "frozen replay experiment identity is missing")
    _require(type(replay.get("threshold")) is int and replay["threshold"] >= 1, "frozen replay threshold is invalid")
    _require(replay.get("cohort_cases") == candidate.get("cohort_cases"), "frozen replay cohort substitution")
    _verify_probe_plan(candidate, replay.get("probe_plan"))
    provenance = replay.get("evidence_provenance")
    _require(isinstance(provenance, dict), "frozen replay evidence provenance is missing")
    _require(provenance.get("native_holdout_report_sha256") == candidate["native_holdout_report_sha256"], "native evidence binding mismatch")
    _require(provenance.get("cohort_results_sha256") == candidate["cohort_results_sha256"], "cohort evidence binding mismatch")
    _require(_SHA.fullmatch(str(provenance.get("syntax_log_sha256", ""))), "syntax evidence binding is missing")
    _require(provenance.get("production_pid_state_yaml_unchanged") is True and provenance.get("capture_and_handoff_complete") is True, "underlying evidence preservation is missing")
    for field in ("syntax_authenticated", "candidate_loaded", "attack_replay_passed", "normal_replay_passed", "negative_control_passed", "production_unchanged"):
        _require(replay.get(field) is True, f"frozen replay {field} is not proven")
    _require(replay.get("normal_false_positive_count") == 0, "frozen replay Normal false positives")
    _require(replay.get("negative_control_false_positive_count") == 0, "frozen replay negative-control false positives")
    _require(replay.get("approved") is False and replay.get("deployed") is False, "frozen replay changed safety flags")


def prepare_frozen_replay_evidence(candidate, native_holdout_report, cohort_results, metadata):
    """Derive unsigned replay evidence from already verified native artifacts."""
    _verify_candidate_shape(candidate)
    _require(isinstance(native_holdout_report, dict), "native holdout report is required")
    _require(isinstance(cohort_results, dict), "cohort results are required")
    _require(isinstance(metadata, dict), "frozen metadata is required")
    _require(native_holdout_report.get("candidate_holdout_pass") is True, "native holdout did not pass")
    _require(native_holdout_report.get("approved") is False and native_holdout_report.get("deployed") is False, "native holdout is not review-only")
    _require(native_holdout_report.get("production_pid_state_yaml_unchanged") is True, "native production preservation is missing")
    _require(_SHA.fullmatch(str(native_holdout_report.get("syntax_log_sha256", ""))), "native syntax evidence hash is missing")
    _require(cohort_results.get("capture_and_handoff_complete") is True, "verified capture/handoff evidence is missing")
    _require(cohort_results.get("approved") is False and cohort_results.get("deployed") is False, "cohort results are not review-only")
    _require(metadata.get("rule_sha256") == candidate["rule_sha256"], "metadata rule hash mismatch")
    _require(type(metadata.get("normal_cal_max_rst")) is int and metadata["normal_cal_max_rst"] >= 0, "frozen threshold provenance is missing")
    _require(metadata.get("normal_calibration_provenance", {}).get("final_holdout_used") is False, "holdout was used for calibration")

    raw_report_cases = native_holdout_report.get("cases")
    _require(isinstance(raw_report_cases, list) and len(raw_report_cases) == 6, "native report must contain six cases")
    report_cases = {case.get("case"): case for case in raw_report_cases}
    _require(len(report_cases) == len(raw_report_cases), "native report contains duplicate cases")
    _require(set(report_cases) == {case["case"] for case in candidate["cohort_cases"]}, "native report cohort substitution")
    probe_plan = []
    for case in candidate["cohort_cases"]:
        report_case = report_cases[case["case"]]
        _require(report_case.get("label") == case["label"], "native report label mismatch")
        _require(report_case.get("run_id") == case["run_id"], "native report run ID mismatch")
        _require(report_case.get("pcap_sha256") == case["pcap_sha256"], "native report PCAP mismatch")
        _require(type(report_case.get("alerts")) is int and report_case["alerts"] >= 0, "native report alert count missing")
        probe_plan.append({
            "case": case["case"],
            "label": case["label"],
            "scenario": _scenario_for_case(case),
            "pcap_sha256": case["pcap_sha256"],
            "expected_alert": case["label"] == "ATTACK",
        })
    _verify_probe_plan(candidate, probe_plan)
    attack = [report_cases[name] for name in report_cases if report_cases[name].get("label") == "ATTACK"]
    normal = [report_cases[name] for name in report_cases if report_cases[name].get("label") == "NORMAL"]
    negative = [report_cases[name] for name in ("N2", "N3")]
    return {
        "schema_version": FROZEN_REPLAY_SCHEMA,
        "candidate_id": candidate["candidate_id"],
        "run_id": candidate["run_id"],
        "sid": SID,
        "rule_sha256": candidate["rule_sha256"],
        "rule_file_sha256": candidate["rule_file_sha256"],
        "freeze_sha256": candidate["freeze_sha256"],
        "cohort_results_sha256": candidate["cohort_results_sha256"],
        "native_holdout_report_sha256": candidate["native_holdout_report_sha256"],
        "cohort_cases_sha256": candidate["cohort_cases_sha256"],
        "baseline_rules_sha256": candidate["baseline_rules_sha256"],
        "pcap_sha256": candidate["pcap_sha256"],
        "model_sha256": candidate["model_sha256"],
        "calibration_sha256": candidate["calibration_sha256"],
        "experiment_id": native_holdout_report.get("evidence_dir"),
        "threshold": metadata["normal_cal_max_rst"] + 1,
        "cohort_cases": [dict(case) for case in candidate["cohort_cases"]],
        "probe_plan": probe_plan,
        "syntax_authenticated": True,
        "candidate_loaded": all(case["alerts"] > 0 for case in attack),
        "attack_replay_passed": len(attack) == 3 and all(case["alerts"] > 0 for case in attack),
        "normal_replay_passed": len(normal) == 3 and all(case["alerts"] == 0 for case in normal),
        "negative_control_passed": len(negative) == 2 and all(case["alerts"] == 0 for case in negative),
        "normal_false_positive_count": sum(case["alerts"] > 0 for case in normal),
        "negative_control_false_positive_count": sum(case["alerts"] > 0 for case in negative),
        "production_unchanged": native_holdout_report["production_pid_state_yaml_unchanged"],
        "approved": False,
        "deployed": False,
        "evidence_provenance": {
            "native_holdout_report_sha256": candidate["native_holdout_report_sha256"],
            "cohort_results_sha256": candidate["cohort_results_sha256"],
            "syntax_log_sha256": native_holdout_report["syntax_log_sha256"],
            "production_pid_state_yaml_unchanged": native_holdout_report["production_pid_state_yaml_unchanged"],
            "capture_and_handoff_complete": cohort_results["capture_and_handoff_complete"],
        },
    }


def sign_frozen_replay_attestation(candidate, replay, private_pem, password):
    _verify_candidate_shape(candidate)
    _verify_replay_shape(candidate, replay)
    return sign_record(replay, private_pem, password, domain=FROZEN_REPLAY_DOMAIN)


def verify_frozen_replay_attestation(candidate, replay, public_pem):
    try:
        _verify_candidate_shape(candidate)
        _verify_replay_shape(candidate, replay)
    except FrozenCandidateError:
        return False
    return verify_record(replay, public_pem, domain=FROZEN_REPLAY_DOMAIN)


def verify_frozen_runtime_result(candidate, replay, result, runtime_public_pem):
    _verify_candidate_shape(candidate)
    _verify_replay_shape(candidate, replay)
    _require(isinstance(result, dict) and result.get("schema_version") == FROZEN_RUNTIME_SCHEMA, "runtime result schema mismatch")
    _require(result.get("candidate_id") == candidate["candidate_id"], "runtime candidate identity mismatch")
    _require(result.get("sid") == SID, "runtime SID mismatch")
    _require(result.get("rule_file_sha256") == candidate["rule_file_sha256"], "runtime rule hash mismatch")
    _require(result.get("replay_evidence_sha256") == _digest(replay), "runtime replay evidence hash mismatch")
    _require(_SHA.fullmatch(str(result.get("owner_authorization_sha256", ""))), "runtime owner authorization hash missing")
    _require(type(result.get("elapsed_seconds")) in (int, float) and result["elapsed_seconds"] >= 0, "runtime elapsed time missing")
    _require(result.get("max_runtime_seconds") == 300 and result["elapsed_seconds"] <= 300, "runtime deadline exceeded")
    _require(result.get("deadline_enforced") is True, "runtime deadline was not enforced")
    _require(isinstance(result.get("probe_results"), list), "runtime probe results missing")
    expected = {probe["case"]: probe for probe in replay["probe_plan"]}
    active = {}
    rollback = {}
    for probe in result["probe_results"]:
        _require(isinstance(probe, dict), "invalid runtime probe result")
        name = probe.get("case")
        phase = probe.get("phase")
        _require(name in expected, "runtime probe case is not in signed cohort")
        _require(probe.get("pcap_sha256") == expected[name]["pcap_sha256"], "runtime probe PCAP mismatch")
        _require(probe.get("label") == expected[name]["label"], "runtime probe label mismatch")
        _require(probe.get("scenario") == expected[name]["scenario"], "runtime probe scenario mismatch")
        target = active if phase == "active" else rollback if phase == "rollback" else None
        _require(target is not None and name not in target, "runtime probe phase duplicate or invalid")
        target[name] = probe
        expected_alert = expected[name]["expected_alert"] if phase == "active" else False
        _require(probe.get("expected_alert") is expected_alert, "runtime probe expectation mismatch")
        _require(type(probe.get("candidate_alerts")) is int and probe["candidate_alerts"] >= 0, "runtime probe alert count invalid")
        if phase == "active":
            _require((probe["candidate_alerts"] > 0) is expected_alert, "runtime active probe result mismatch")
        else:
            _require(probe["candidate_alerts"] == 0, "runtime rollback probe result mismatch")
    _require(set(active) == set(expected) and set(rollback) == set(expected), "runtime probes do not cover exact cohort in both phases")
    for field in (
        "candidate_loaded", "attack_replay_passed", "normal_replay_passed",
        "negative_control_passed", "rollback_verified", "post_rollback_verified",
        "child_process_cleanup_verified", "production_unchanged",
    ):
        _require(result.get(field) is True, f"runtime result {field} is not verified")
    _require(result.get("outcome") == "VERIFIED_ISOLATED_ACTIVATION_AND_ROLLBACK", "runtime result is not accepted")
    _require(result.get("approved") is False and result.get("deployed") is False, "runtime result changed safety flags")
    _require(verify_record(result, runtime_public_pem, domain=FROZEN_RUNTIME_DOMAIN), "untrusted runtime result signature")
    return True


def build_frozen_owner_authorization(
    candidate, replay, *, replay_public_pem, owner_private_pem,
    owner_private_password, owner_public_pem, runtime_public_pem, approver_identity,
    isolated_root, runtime_id, target_vm, interface, nonce, now=None,
):
    """Sign separate, candidate-specific one-shot owner authorization."""
    from netids.key_pins import require_pinned_role_keys

    if not verify_frozen_replay_attestation(candidate, replay, replay_public_pem):
        raise FrozenCandidateError("trusted frozen replay evidence is required")
    require_pinned_role_keys(replay_public_pem, owner_public_pem)
    _require(private_key_matches_public(owner_private_pem, owner_private_password, owner_public_pem), "owner private/public key mismatch")
    try:
        runtime_signer_sha256 = public_key_fingerprint(runtime_public_pem)
    except (TypeError, ValueError, UnicodeError) as exc:
        raise FrozenCandidateError("invalid runtime signer public key") from exc
    _require(isinstance(approver_identity, str) and approver_identity.strip(), "approver identity is required")
    _require(isinstance(nonce, str) and re.fullmatch(r"[0-9a-f]{32}", nonce), "invalid one-shot nonce")
    now = now or datetime.now(timezone.utc)
    _require(now.tzinfo is not None, "authorization time must be timezone-aware")
    record = {
        "schema_version": FROZEN_OWNER_SCHEMA,
        "candidate_id": candidate["candidate_id"],
        "run_id": candidate["run_id"],
        "sid": SID,
        "rule_sha256": candidate["rule_sha256"],
        "rule_file_sha256": candidate["rule_file_sha256"],
        "freeze_sha256": candidate["freeze_sha256"],
        "cohort_results_sha256": candidate["cohort_results_sha256"],
        "baseline_rules_sha256": candidate["baseline_rules_sha256"],
        "replay_evidence_sha256": _digest(replay),
        "runtime_signer_sha256": runtime_signer_sha256,
        "runtime_id": runtime_id,
        "target_vm": target_vm,
        "interface": interface,
        "isolated_root": str(isolated_root),
        "environment": "isolated-lab",
        "operation": "activate",
        "rollback_required": True,
        "max_activation_seconds": 300,
        "approver_identity": approver_identity.strip(),
        "approved_at": now.astimezone(timezone.utc).isoformat(),
        "expires_at": (now + timedelta(minutes=15)).astimezone(timezone.utc).isoformat(),
        "nonce": nonce,
    }
    signed = sign_record(record, owner_private_pem, owner_private_password, domain=FROZEN_OWNER_DOMAIN)
    if not verify_record(signed, owner_public_pem, domain=FROZEN_OWNER_DOMAIN):
        raise FrozenCandidateError("owner private key does not match owner public key")
    return signed


def verify_frozen_owner_authorization(
    candidate, replay, authorization, replay_public_pem, owner_public_pem,
    runtime_public_pem, *, now=None,
):
    from netids.key_pins import require_pinned_role_keys

    if not verify_frozen_replay_attestation(candidate, replay, replay_public_pem):
        return False
    try:
        require_pinned_role_keys(replay_public_pem, owner_public_pem)
        _require(authorization.get("schema_version") == FROZEN_OWNER_SCHEMA, "owner authorization schema mismatch")
        _require(authorization.get("candidate_id") == candidate["candidate_id"], "owner authorization candidate mismatch")
        _require(authorization.get("run_id") == candidate["run_id"], "owner authorization run mismatch")
        for field in ("sid", "rule_sha256", "rule_file_sha256", "freeze_sha256", "cohort_results_sha256", "baseline_rules_sha256"):
            _require(authorization.get(field) == candidate.get(field), f"owner authorization {field} mismatch")
        _require(authorization.get("replay_evidence_sha256") == _digest(replay), "owner authorization replay mismatch")
        _require(authorization.get("runtime_signer_sha256") == public_key_fingerprint(runtime_public_pem), "runtime signer mismatch")
        _require(authorization.get("rollback_required") is True and authorization.get("max_activation_seconds") == 300, "owner authorization scope mismatch")
        _require(authorization.get("operation") == "activate" and authorization.get("environment") == "isolated-lab", "owner authorization operation mismatch")
        now = now or datetime.now(timezone.utc)
        approved = datetime.fromisoformat(authorization["approved_at"])
        expires = datetime.fromisoformat(authorization["expires_at"])
        _require(approved.tzinfo is not None and expires.tzinfo is not None, "owner authorization times must be timezone-aware")
        _require(expires > approved and expires > now and approved <= now + timedelta(minutes=5), "owner authorization expired or not yet valid")
        _require(expires - approved <= timedelta(hours=24), "owner authorization window is too long")
        _require(verify_record(authorization, owner_public_pem, domain=FROZEN_OWNER_DOMAIN), "invalid owner authorization signature")
    except (FrozenCandidateError, TypeError, ValueError):
        return False
    return True
