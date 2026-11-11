"""Validated, review-only correlation envelopes for lab evidence."""

import hashlib
import re
from typing import Any, Dict, Optional


SHA256 = re.compile(r"^[0-9a-f]{64}$")
RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
HYBRID_CLASSIFICATIONS = frozenset({
    "reconnaissance_consistent",
    "anomalous_not_reconnaissance",
    "unavailable_missing_calibration",
})
REVIEW_STATUSES = frozenset({
    "no_candidate",
    "needs_review",
    "rejected_known_false_positive",
    "rejected_validation_failure",
    "validated_for_review",
})


def _hash(value: Any, field: str) -> str:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise ValueError(f"{field} must be a lowercase SHA256")
    return value


def stable_document_id(run_id: str, pcap_sha256: str) -> str:
    if not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id):
        raise ValueError("Invalid run_id")
    _hash(pcap_sha256, "pcap_sha256")
    return hashlib.sha256(f"{run_id}:{pcap_sha256}".encode()).hexdigest()


def build_correlation_envelope(
    *,
    run_id: str,
    scenario: str,
    pcap_sha256: str,
    manifest_sha256: str,
    eve_output_sha256: str,
    model_sha256: str,
    calibration_sha256: str,
    ai_summary_document_id: str,
        ai_summary_sha256: str,
    suricata_version: str,
    replay_rule_sha256: str,
    matched_eve_events: int,
    matched_flows: int,
    hybrid_classification: str,
    review_status: str,
    sid: Optional[int],
    correlation_level: str,
) -> Dict[str, Any]:
    if not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id):
        raise ValueError("Invalid run_id")
    if scenario not in {"attack", "normal"}:
        raise ValueError("scenario must be attack or normal")
    for name, value in (
        ("pcap_sha256", pcap_sha256),
        ("manifest_sha256", manifest_sha256),
        ("eve_output_sha256", eve_output_sha256),
        ("model_sha256", model_sha256),
        ("calibration_sha256", calibration_sha256),
        ("replay_rule_sha256", replay_rule_sha256),
    ):
        _hash(value, name)
    if not isinstance(ai_summary_document_id, str) or not SHA256.fullmatch(
        ai_summary_document_id
    ):
        raise ValueError("ai_summary_document_id must be a SHA256")
    _hash(ai_summary_sha256, "ai_summary_sha256")
    if type(matched_eve_events) is not int or matched_eve_events < 0:
        raise ValueError("matched_eve_events must be non-negative")
    if type(matched_flows) is not int or matched_flows < 0:
        raise ValueError("matched_flows must be non-negative")
    if hybrid_classification not in HYBRID_CLASSIFICATIONS:
        raise ValueError("Unsupported hybrid_classification")
    if review_status not in REVIEW_STATUSES:
        raise ValueError("Unsupported review_status")
    if sid is not None and (type(sid) is not int or sid < 1):
        raise ValueError("Invalid sid")
    if correlation_level not in {"event_verified", "session_verified", "unverified"}:
        raise ValueError("Invalid correlation_level")
    return {
        "schema_version": "suricata_ai_correlation_v1",
        "run_id": run_id,
        "scenario": scenario,
        "pcap_sha256": pcap_sha256,
        "manifest_sha256": manifest_sha256,
        "eve_output_sha256": eve_output_sha256,
        "model_sha256": model_sha256,
        "calibration_sha256": calibration_sha256,
        "ai_summary_document_id": ai_summary_document_id,
        "ai_summary_sha256": ai_summary_sha256,
        "suricata_version": suricata_version,
        "replay_rule_sha256": replay_rule_sha256,
        "matching_eve_events": matched_eve_events,
        "matched_flows": matched_flows,
        "hybrid_classification": hybrid_classification,
        "review_status": review_status,
        "sid": sid,
        "correlation_level": correlation_level,
        "correlation_verified": correlation_level != "unverified",
        "approved": False,
        "deployable": False,
        "deployed": False,
    }
