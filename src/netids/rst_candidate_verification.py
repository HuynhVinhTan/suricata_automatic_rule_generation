"""Offline verification for a frozen, review-only RST candidate.

This module verifies evidence that was produced elsewhere.  It does not train,
calibrate, generate, deploy, approve, or activate a rule.
"""

import hashlib
import json
import re
from pathlib import Path


SHA256 = re.compile(r"^[0-9a-f]{64}$")
SID = 9103005


class RstCandidateVerificationError(ValueError):
    """Raised when frozen RST evidence is missing, inconsistent, or tampered."""


def _sha256(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise RstCandidateVerificationError(f"evidence file is not regular: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load(path, label):
    try:
        with Path(path).open("r", encoding="utf-8") as stream:
            value = json.load(stream)
    except (OSError, ValueError) as exc:
        raise RstCandidateVerificationError(f"invalid {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise RstCandidateVerificationError(f"{label} must be a JSON object")
    return value


def _hash_field(value, label):
    if not isinstance(value, str) or not SHA256.fullmatch(value.lower()):
        raise RstCandidateVerificationError(f"invalid {label}")
    return value.lower()


def _require(value, expected, label):
    if value != expected:
        raise RstCandidateVerificationError(
            f"{label} mismatch: expected {expected!r}, got {value!r}"
        )


def _complete_capture(metadata):
    return (
        isinstance(metadata, dict)
        and metadata.get("packet_records_complete") is True
        and metadata.get("snaplen_truncated") is False
        and metadata.get("capture_drops") is False
    )


def _case_map(cases, label):
    if not isinstance(cases, list) or len(cases) != 6:
        raise RstCandidateVerificationError(f"{label} must contain six cases")
    result = {}
    run_ids = set()
    pcap_hashes = set()
    for case in cases:
        if not isinstance(case, dict):
            raise RstCandidateVerificationError(f"invalid {label} case")
        name = case.get("case")
        run_id = case.get("run_id")
        pcap = _hash_field(case.get("pcap_sha256"), f"{label} PCAP hash")
        if name in result:
            raise RstCandidateVerificationError(f"duplicate {label} case: {name}")
        if run_id in run_ids:
            raise RstCandidateVerificationError(f"duplicate {label} run ID")
        if pcap in pcap_hashes:
            raise RstCandidateVerificationError(f"duplicate holdout PCAP hash")
        if not isinstance(name, str) or not isinstance(run_id, str):
            raise RstCandidateVerificationError(f"invalid {label} identity")
        result[name] = case
        run_ids.add(run_id)
        pcap_hashes.add(pcap)
    return result, run_ids, pcap_hashes


def _verify_development_evidence(path, freeze, expected_commit):
    development = _load(path, "development evidence")
    _require(development.get("scope"), "G4_DEVELOPMENT_ONLY", "development scope")
    _require(development.get("source_commit"), expected_commit, "development source commit")
    _require(development.get("native_replay_tested"), False, "development native replay flag")
    _require(development.get("independent_final_acceptance"), False, "development acceptance flag")
    _hash_field(development.get("generator_sha256"), "development generator hash")
    _hash_field(development.get("calibration_sha256"), "development calibration hash")
    references = development.get("calibration_references")
    if not isinstance(references, list) or not references:
        raise RstCandidateVerificationError("development calibration references are missing")
    for reference in references:
        if not isinstance(reference, dict):
            raise RstCandidateVerificationError("invalid development calibration reference")
        _require(reference.get("ground_truth_label"), "NORMAL", "calibration label")
        _hash_field(reference.get("sha256"), "calibration PCAP hash")
        if not _complete_capture(reference.get("capture_metadata")):
            raise RstCandidateVerificationError("incomplete calibration capture")
    for field in ("normal_cal_rst_counts", "normal_development_rst_counts", "attack_development_rst_counts"):
        values = development.get(field)
        if not isinstance(values, list) or not values or any(type(value) is not int or value < 0 for value in values):
            raise RstCandidateVerificationError(f"invalid development {field}")
    _require(freeze.get("development_evidence_sha256"), _sha256(path), "development evidence hash")
    return development


def _verify_metadata(rule_path, metadata_path, freeze, sid):
    rule_path = Path(rule_path)
    metadata_path = Path(metadata_path)
    rule_bytes = rule_path.read_bytes()
    rule_sha = _sha256(rule_path)
    _require(freeze.get("rule_file_sha256"), rule_sha, "rule file SHA256")
    metadata_sha = _sha256(metadata_path)
    _require(freeze.get("metadata_sha256"), metadata_sha, "metadata SHA256")
    rule = rule_bytes.decode("utf-8").rstrip("\r\n")
    match = re.search(r"\bsid\s*:\s*(\d+)\s*;", rule)
    if not match or int(match.group(1)) != sid:
        raise RstCandidateVerificationError("frozen rule SID mismatch")
    if "flags:R+;" not in rule:
        raise RstCandidateVerificationError("frozen rule is not an RST signature")
    metadata = _load(metadata_path, "RST metadata")
    _require(metadata.get("schema_version"), "ml_rst_rule_metadata_v1", "RST metadata schema")
    _require(metadata.get("candidate_family"), "rst_response_v1", "RST candidate family")
    _require(metadata.get("rule_sha256"), hashlib.sha256(rule.encode("utf-8")).hexdigest(), "rule content SHA256")
    _require(metadata.get("approved"), False, "metadata approval flag")
    _require(metadata.get("deployed"), False, "metadata deployment flag")
    return rule, metadata


def verify_frozen_rst_candidate(
    *, freeze_path, development_evidence_path, holdout_report_path,
    cohort_results_path, cohort_plan_path, rule_path, metadata_path,
    expected_source_commit, expected_sid=SID, expected_freeze_sha256=None,
    expected_cohort_sha256=None,
):
    """Verify the frozen SID9103005 evidence without changing any artifact."""
    if expected_sid != SID:
        raise RstCandidateVerificationError("only the frozen SID9103005 verifier is supported")
    freeze_path = Path(freeze_path)
    freeze = _load(freeze_path, "acceptance freeze")
    freeze_sha = _sha256(freeze_path)
    if expected_freeze_sha256 is not None:
        _require(freeze_sha, _hash_field(expected_freeze_sha256, "expected freeze SHA256"), "freeze SHA256")
    _require(freeze.get("schema"), "g4_acceptance_freeze_v1", "freeze schema")
    _require(freeze.get("source_commit"), expected_source_commit, "freeze source commit")
    _require(freeze.get("sid"), SID, "freeze SID")
    for field in ("rule_file_sha256", "rule_content_sha256", "metadata_sha256", "development_evidence_sha256"):
        _hash_field(freeze.get(field), f"freeze {field}")
    _require(freeze.get("approved"), False, "freeze approval flag")
    _require(freeze.get("deployed"), False, "freeze deployment flag")
    development = _verify_development_evidence(
        development_evidence_path, freeze, expected_source_commit
    )
    rule, metadata = _verify_metadata(rule_path, metadata_path, freeze, SID)

    cohort_path = Path(cohort_results_path)
    cohort = _load(cohort_path, "cohort results")
    cohort_sha = _sha256(cohort_path)
    if expected_cohort_sha256 is not None:
        _require(cohort_sha, _hash_field(expected_cohort_sha256, "expected cohort SHA256"), "cohort results SHA256")
    _require(cohort.get("freeze_sha256"), freeze_sha, "cohort freeze SHA256")
    _require(cohort.get("sid"), SID, "cohort SID")
    _require(cohort.get("capture_and_handoff_complete"), True, "cohort capture/handoff")
    _require(cohort.get("approved"), False, "cohort approval flag")
    _require(cohort.get("deployed"), False, "cohort deployment flag")
    cohort_cases, cohort_runs, cohort_pcaps = _case_map(cohort.get("cases"), "cohort")
    if any(case.get("receipt", {}).get("status") != "succeeded" for case in cohort_cases.values()):
        raise RstCandidateVerificationError("incomplete worker receipt")
    for case in cohort_cases.values():
        receipt = case["receipt"]
        _require(receipt.get("run_id"), case.get("run_id"), "worker receipt run ID")
        _require(receipt.get("pcap_sha256"), case.get("pcap_sha256"), "worker receipt PCAP hash")
        _require(case.get("hybrid_match"), True, "Hybrid evidence match")

    holdout = _load(holdout_report_path, "native holdout report")
    _require(holdout.get("scope"), "G4_FROZEN_RST_INDEPENDENT_HOLDOUT_NATIVE_REPLAY", "holdout scope")
    _require(holdout.get("sid"), SID, "holdout SID")
    _require(holdout.get("freeze_sha256"), freeze_sha, "holdout freeze SHA256")
    _require(holdout.get("cohort_results_sha256"), cohort_sha, "holdout cohort SHA256")
    _require(holdout.get("rule_file_sha256"), freeze["rule_file_sha256"], "holdout rule SHA256")
    if "Suricata version 8.0.3" not in str(holdout.get("engine")):
        raise RstCandidateVerificationError("holdout engine is not Suricata 8.0.3")
    _require(holdout.get("production_pid_state_yaml_unchanged"), True, "production state preservation")
    holdout_cases, holdout_runs, holdout_pcaps = _case_map(holdout.get("cases"), "holdout")
    if set(holdout_cases) != set(cohort_cases) or holdout_runs != cohort_runs or holdout_pcaps != cohort_pcaps:
        raise RstCandidateVerificationError("cohort and holdout records disagree")
    labels = [case.get("label") for case in holdout_cases.values()]
    if labels.count("ATTACK") != 3 or labels.count("NORMAL") != 3:
        raise RstCandidateVerificationError("holdout must contain three Attack and three Normal cases")
    for case in holdout_cases.values():
        if type(case.get("alerts")) is not int or case["alerts"] < 0:
            raise RstCandidateVerificationError("invalid holdout alert count")
        if case["label"] == "ATTACK" and case["alerts"] < 1:
            raise RstCandidateVerificationError("holdout Attack false negative")
        if case["label"] == "NORMAL" and case["alerts"] != 0:
            raise RstCandidateVerificationError("holdout Normal false positive")

    plan = _load(cohort_plan_path, "cohort plan")
    _require(plan.get("freeze_sha256"), freeze_sha, "plan freeze SHA256")
    _require(plan.get("sid"), SID, "plan SID")
    planned = plan.get("cases")
    if not isinstance(planned, list) or {item.get("case") for item in planned} != set(holdout_cases):
        raise RstCandidateVerificationError("cohort plan does not bind holdout cases")
    prior_pcaps = set(plan.get("prior_pcap_sha256", []))
    if holdout_pcaps & prior_pcaps:
        raise RstCandidateVerificationError("holdout PCAP overlaps prior development evidence")
    development_pcaps = {
        reference["sha256"] for reference in development["calibration_references"]
    }
    development_cases = freeze.get("development_cases", [])
    development_pcaps.update(
        case.get("pcap_sha256") for case in development_cases if isinstance(case, dict)
    )
    if holdout_pcaps & development_pcaps:
        raise RstCandidateVerificationError("holdout PCAP overlaps development evidence")
    metrics = {
        "TP": sum(case["label"] == "ATTACK" and case["alerts"] > 0 for case in holdout_cases.values()),
        "FN": sum(case["label"] == "ATTACK" and case["alerts"] == 0 for case in holdout_cases.values()),
        "FP": sum(case["label"] == "NORMAL" and case["alerts"] > 0 for case in holdout_cases.values()),
        "TN": sum(case["label"] == "NORMAL" and case["alerts"] == 0 for case in holdout_cases.values()),
    }
    _require(holdout.get("TP"), metrics["TP"], "holdout TP")
    _require(holdout.get("FN"), metrics["FN"], "holdout FN")
    _require(holdout.get("FP"), metrics["FP"], "holdout FP")
    _require(holdout.get("TN"), metrics["TN"], "holdout TN")
    _require(holdout.get("candidate_holdout_pass"), True, "candidate holdout result")
    _require(holdout.get("approved"), False, "holdout approval flag")
    _require(holdout.get("deployed"), False, "holdout deployment flag")
    return {
        "verified": True,
        "status": "candidate_holdout_verified",
        "sid": SID,
        "rule_file_sha256": freeze["rule_file_sha256"],
        "rule_content_sha256": freeze["rule_content_sha256"],
        "freeze_sha256": freeze_sha,
        "cohort_results_sha256": cohort_sha,
        "metrics": metrics,
        "approved": False,
        "deployed": False,
        "bounded_laboratory_signature": True,
        "hybrid_equivalent": False,
        "rule": rule,
        "metadata": metadata,
    }


def build_g5_acceptance_request(verification):
    """Create a candidate-bound, owner-authorized G5 runtime request only."""
    if not isinstance(verification, dict) or verification.get("verified") is not True:
        raise RstCandidateVerificationError("G5 request requires verified candidate evidence")
    if verification.get("approved") is not False:
        raise RstCandidateVerificationError("G5 request cannot start from an approved candidate")
    if verification.get("deployed") is not False:
        raise RstCandidateVerificationError("G5 request cannot start from a deployed candidate")
    if verification.get("hybrid_equivalent") is not False:
        raise RstCandidateVerificationError("G5 request requires bounded non-Hybrid-equivalent evidence")
    for field in ("sid", "rule_file_sha256", "freeze_sha256", "cohort_results_sha256"):
        if field not in verification:
            raise RstCandidateVerificationError(f"G5 request missing {field}")
    for field in ("rule_file_sha256", "freeze_sha256", "cohort_results_sha256"):
        _hash_field(verification[field], f"G5 {field}")
    return {
        "schema_version": "g5_candidate_acceptance_request_v1",
        "status": "awaiting_owner_runtime",
        "operation": "isolated_activation_and_rollback",
        "sid": verification["sid"],
        "rule_file_sha256": verification["rule_file_sha256"],
        "freeze_sha256": verification["freeze_sha256"],
        "cohort_results_sha256": verification["cohort_results_sha256"],
        "requires_owner_authorization": True,
        "requires_isolated_runtime": True,
        "rollback_required": True,
        "approved": False,
        "deployed": False,
        "production_activation": False,
        "required_runtime_checks": [
            "candidate-only rule syntax and hash verification",
            "isolated Normal and negative-control replay",
            "isolated Attack replay with candidate alert attribution",
            "owner-visible rollback and post-rollback state verification",
        ],
    }
