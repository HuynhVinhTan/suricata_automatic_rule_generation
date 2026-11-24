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

from netids.lifecycle_ed25519 import sign_record, verify_record


FROZEN_CANDIDATE_SCHEMA = "g5_frozen_rst_candidate_v1"
FROZEN_REPLAY_SCHEMA = "g5_frozen_rst_replay_attestation_v1"
FROZEN_OWNER_SCHEMA = "g5_frozen_owner_authorization_v1"
FROZEN_RUNTIME_SCHEMA = "g5_frozen_runtime_acceptance_v1"
FROZEN_REPLAY_DOMAIN = "g5-frozen-replay-v1"
FROZEN_OWNER_DOMAIN = "g5-frozen-owner-v1"
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
    return cases


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
    for field in ("candidate_id", "sid", "rule_file_sha256", "freeze_sha256", "cohort_results_sha256", "baseline_rules_sha256"):
        _require(replay.get(field) == candidate.get(field), f"frozen replay {field} mismatch")
    for field in ("pcap_sha256", "model_sha256", "calibration_sha256"):
        _require(replay.get(field) == candidate.get(field), f"frozen replay {field} mismatch")
    _require(isinstance(replay.get("experiment_id"), str) and replay["experiment_id"].strip(), "frozen replay experiment identity is missing")
    _require(type(replay.get("threshold")) is int and replay["threshold"] >= 1, "frozen replay threshold is invalid")
    _require(replay.get("cohort_cases") == candidate.get("cohort_cases"), "frozen replay cohort substitution")
    for field in ("syntax_authenticated", "candidate_loaded", "attack_replay_passed", "normal_replay_passed", "negative_control_passed", "production_unchanged"):
        _require(replay.get(field) is True, f"frozen replay {field} is not proven")
    _require(replay.get("normal_false_positive_count") == 0, "frozen replay Normal false positives")
    _require(replay.get("negative_control_false_positive_count") == 0, "frozen replay negative-control false positives")
    _require(replay.get("approved") is False and replay.get("deployed") is False, "frozen replay changed safety flags")


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


def verify_frozen_runtime_result(candidate, replay, result):
    _verify_candidate_shape(candidate)
    _verify_replay_shape(candidate, replay)
    _require(isinstance(result, dict) and result.get("schema_version") == FROZEN_RUNTIME_SCHEMA, "runtime result schema mismatch")
    _require(result.get("candidate_id") == candidate["candidate_id"], "runtime candidate identity mismatch")
    _require(result.get("sid") == SID, "runtime SID mismatch")
    _require(result.get("rule_file_sha256") == candidate["rule_file_sha256"], "runtime rule hash mismatch")
    _require(result.get("replay_evidence_sha256") == _digest(replay), "runtime replay evidence hash mismatch")
    for field in (
        "candidate_loaded", "attack_replay_passed", "normal_replay_passed",
        "negative_control_passed", "rollback_verified", "post_rollback_verified",
        "child_process_cleanup_verified", "production_unchanged",
    ):
        _require(result.get(field) is True, f"runtime result {field} is not verified")
    _require(result.get("outcome") == "VERIFIED_ISOLATED_ACTIVATION_AND_ROLLBACK", "runtime result is not accepted")
    _require(result.get("approved") is False and result.get("deployed") is False, "runtime result changed safety flags")
    return True


def build_frozen_owner_authorization(
    candidate, replay, *, replay_public_pem, owner_private_pem,
    owner_private_password, owner_public_pem, approver_identity,
    isolated_root, runtime_id, target_vm, interface, nonce, now=None,
):
    """Sign separate, candidate-specific one-shot owner authorization."""
    from netids.key_pins import require_pinned_role_keys

    if not verify_frozen_replay_attestation(candidate, replay, replay_public_pem):
        raise FrozenCandidateError("trusted frozen replay evidence is required")
    require_pinned_role_keys(replay_public_pem, owner_public_pem)
    _require(isinstance(approver_identity, str) and approver_identity.strip(), "approver identity is required")
    _require(isinstance(nonce, str) and re.fullmatch(r"[0-9a-f]{32}", nonce), "invalid one-shot nonce")
    now = now or datetime.now(timezone.utc)
    _require(now.tzinfo is not None, "authorization time must be timezone-aware")
    record = {
        "schema_version": FROZEN_OWNER_SCHEMA,
        "candidate_id": candidate["candidate_id"],
        "run_id": candidate["run_id"],
        "sid": SID,
        "rule_file_sha256": candidate["rule_file_sha256"],
        "freeze_sha256": candidate["freeze_sha256"],
        "cohort_results_sha256": candidate["cohort_results_sha256"],
        "baseline_rules_sha256": candidate["baseline_rules_sha256"],
        "replay_evidence_sha256": _digest(replay),
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


def verify_frozen_owner_authorization(candidate, replay, authorization, replay_public_pem, owner_public_pem):
    from netids.key_pins import require_pinned_role_keys

    if not verify_frozen_replay_attestation(candidate, replay, replay_public_pem):
        return False
    try:
        require_pinned_role_keys(replay_public_pem, owner_public_pem)
        _require(authorization.get("schema_version") == FROZEN_OWNER_SCHEMA, "owner authorization schema mismatch")
        _require(authorization.get("candidate_id") == candidate["candidate_id"], "owner authorization candidate mismatch")
        _require(authorization.get("run_id") == candidate["run_id"], "owner authorization run mismatch")
        for field in ("sid", "rule_file_sha256", "freeze_sha256", "cohort_results_sha256", "baseline_rules_sha256"):
            _require(authorization.get(field) == candidate.get(field), f"owner authorization {field} mismatch")
        _require(authorization.get("replay_evidence_sha256") == _digest(replay), "owner authorization replay mismatch")
        _require(authorization.get("rollback_required") is True and authorization.get("max_activation_seconds") == 300, "owner authorization scope mismatch")
        _require(authorization.get("operation") == "activate" and authorization.get("environment") == "isolated-lab", "owner authorization operation mismatch")
        _require(verify_record(authorization, owner_public_pem, domain=FROZEN_OWNER_DOMAIN), "invalid owner authorization signature")
    except (FrozenCandidateError, TypeError, ValueError):
        return False
    return True
