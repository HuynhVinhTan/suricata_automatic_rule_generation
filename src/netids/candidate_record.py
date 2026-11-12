"""Fail-closed, candidate-specific provenance records for generated rules.

This module records what is known locally. It never turns review flags into
replay evidence or approval; those require a separately signed execution
attestation from a trusted Suricata runner.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from netids.rulegen import collect_sids
from netids.lifecycle_ed25519 import verify_record


class CandidateRecordError(ValueError):
    pass


_HEX = re.compile(r"^[0-9a-f]{64}$")
_RUN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
APPROVED_CASE_MANIFEST_SHA256 = "57aa92f0a63bd2f8fe037904d0aecb2e2414031d5b9af8f08e5c9bbf73eddeba"


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha_file(path: Path) -> str:
    return _sha_bytes(path.read_bytes())


def _required_sha(value: object, name: str) -> str:
    if not isinstance(value, str) or not _HEX.fullmatch(value):
        raise CandidateRecordError(f"{name} must be a lowercase SHA-256")
    return value


def _candidate_id(record: dict) -> str:
    identity = {
        key: record[key]
        for key in (
            "run_id", "sid", "rule_sha256", "pcap_sha256", "model_sha256",
            "calibration_sha256", "decision_manifest_sha256",
        )
    }
    return _sha_bytes(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def expected_candidate_runtime_id(candidate: dict, *, target_vm: str, interface: str, isolated_root: str) -> str:
    """Derive the reviewed runtime identity from candidate and exact scope."""
    if target_vm != "suricata-vm1" or interface != "lo":
        raise CandidateRecordError("Candidate runtime is restricted to VM1 loopback")
    root_sha = _sha_bytes(isolated_root.encode("utf-8"))[:12]
    return f"{target_vm}:candidate-{candidate['sid']}-{candidate['candidate_id'][:12]}-{root_sha}:{interface}"


def _read_json(path: Path, name: str) -> dict:
    if path.is_symlink() or not path.is_file():
        raise CandidateRecordError(f"Missing or unsafe {name}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CandidateRecordError(f"Invalid {name}") from exc
    if not isinstance(value, dict):
        raise CandidateRecordError(f"{name} must be an object")
    return value


def build_candidate_record(artifact_dir: Path, calibration_manifest: Path, baseline_rules: Path) -> dict:
    root = Path(artifact_dir).resolve(strict=True)
    rule_path = root / "ml-generated.rules"
    metadata_path = root / "ml-generated.metadata.json"
    review_path = root / "review.json"
    if any(path.is_symlink() or not path.is_file() for path in (rule_path, metadata_path, review_path)):
        raise CandidateRecordError("Candidate artifacts are missing or unsafe")
    raw_rule = rule_path.read_bytes()
    if raw_rule.count(b"\n") != 1 or not raw_rule.endswith(b"\n") or b"\r" in raw_rule:
        raise CandidateRecordError("Candidate rule must contain exactly one terminal LF")
    try:
        rule = raw_rule[:-1].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CandidateRecordError("Candidate rule is not UTF-8") from exc
    metadata = _read_json(metadata_path, "candidate metadata")
    review = _read_json(review_path, "candidate review")
    run_id = metadata.get("run_id")
    if not isinstance(run_id, str) or not _RUN.fullmatch(run_id):
        raise CandidateRecordError("Candidate run ID is invalid")
    if metadata.get("schema_version") != "ml_rule_metadata_v1" or review.get("schema_version") != "lab_rule_review_v0_2":
        raise CandidateRecordError("Unsupported candidate artifact schema")
    if any(metadata.get(key) is not False for key in ("approved", "deployable", "deployed")):
        raise CandidateRecordError("Candidate safety flags must be false")
    if metadata.get("status") not in (None, "needs_review") or review.get("status") != "needs_review":
        raise CandidateRecordError("Candidate is not review-only")
    try:
        sids = collect_sids([rule])
    except (TypeError, ValueError) as exc:
        raise CandidateRecordError("Candidate rule SID is invalid") from exc
    if len(sids) != 1:
        raise CandidateRecordError("Candidate rule must contain exactly one SID")
    sid = next(iter(sids))
    if review.get("generated_rule_sid") != sid:
        raise CandidateRecordError("Review SID does not match candidate rule")
    rule_sha = _sha_bytes(rule.encode("utf-8"))
    if metadata.get("rule_sha256") != rule_sha:
        raise CandidateRecordError("Candidate rule SHA mismatch")
    pcap_sha = _required_sha(metadata.get("pcap_sha256"), "PCAP SHA")
    model_sha = _required_sha(metadata.get("model_sha256"), "model SHA")
    if review.get("source_pcap_sha256") != pcap_sha or review.get("model_sha256") != model_sha:
        raise CandidateRecordError("Review provenance does not match metadata")
    calibration_path = Path(calibration_manifest)
    calibration = _read_json(calibration_path, "calibration manifest")
    calibration_sha = _sha_file(calibration_path)
    threshold = calibration.get("threshold_provenance")
    decision_sha = _required_sha(
        threshold.get("calibration_decision_sha256") if isinstance(threshold, dict) else None,
        "decision manifest SHA",
    )
    baseline_path = Path(baseline_rules)
    if baseline_path.is_symlink() or not baseline_path.is_file():
        raise CandidateRecordError("Baseline rules are missing or unsafe")
    try:
        if sid in collect_sids(baseline_path.read_text(encoding="utf-8").splitlines()):
            raise CandidateRecordError("Candidate SID collision with baseline rules")
    except UnicodeError as exc:
        raise CandidateRecordError("Baseline rules are not UTF-8") from exc
    record = {
        "schema_version": "candidate_record_v1",
        "candidate_record_schema": "candidate_record_v1",
        "run_id": run_id,
        "sid": sid,
        "rule": rule,
        "rule_sha256": rule_sha,
        "source_rule_file_sha256": _sha_file(rule_path),
        "source_metadata_sha256": _sha_file(metadata_path),
        "review_sha256": _sha_file(review_path),
        "pcap_sha256": pcap_sha,
        "model_sha256": model_sha,
        "calibration_sha256": calibration_sha,
        "decision_manifest_sha256": decision_sha,
        "baseline_rules_sha256": _sha_file(baseline_path),
        "replay_evidence": {"status": "not_available", "reason": "No local Suricata execution evidence supplied"},
        "approved": False,
        "deployable": False,
        "deployed": False,
    }
    record["candidate_id"] = _candidate_id(record)
    if not verify_candidate_record(record):
        raise CandidateRecordError("Constructed candidate record failed self-verification")
    return record


def verify_candidate_record(record: object) -> bool:
    if not isinstance(record, dict) or record.get("schema_version") != "candidate_record_v1":
        return False
    required = ("candidate_id", "run_id", "rule_sha256", "pcap_sha256", "model_sha256", "calibration_sha256", "decision_manifest_sha256", "baseline_rules_sha256")
    if not isinstance(record.get("run_id"), str) or not _RUN.fullmatch(record["run_id"]):
        return False
    if any(not isinstance(record.get(key), str) or not _HEX.fullmatch(record[key]) for key in required if key not in {"candidate_id", "run_id"}):
        return False
    if not isinstance(record.get("candidate_id"), str) or not _HEX.fullmatch(record["candidate_id"]):
        return False
    if type(record.get("sid")) is not int or not 1 <= record["sid"] <= 4294967295:
        return False
    expected = _candidate_id(record)
    if record["candidate_id"] != expected:
        return False
    if any(record.get(key) is not False for key in ("approved", "deployable", "deployed")):
        return False
    replay = record.get("replay_evidence")
    return isinstance(replay, dict) and replay.get("status") in {"not_available", "verified"}


def verify_signed_replay_evidence(candidate: dict, evidence: dict, public_key: bytes) -> bool:
    """Accept replay evidence only from the trusted execution signer."""
    if not verify_candidate_record(candidate) or not verify_record(
        evidence, public_key, domain="isolated-replay-v1"
    ):
        return False
    if any(evidence.get(key) != candidate.get(key) for key in (
        "candidate_id", "run_id", "sid", "rule_sha256", "pcap_sha256",
        "model_sha256", "calibration_sha256", "decision_manifest_sha256",
    )):
        return False
    if evidence.get("suricata_version", "").find("8.0.3") < 0:
        return False
    if evidence.get("syntax_authenticated") is not True:
        return False
    if (
        evidence.get("case_manifest_schema") != "candidate_independent_replay_manifest_v1"
        or evidence.get("case_manifest_sha256") != APPROVED_CASE_MANIFEST_SHA256
        or evidence.get("minimum_attack_cases") != 2
        or evidence.get("minimum_normal_cases") != 3
    ):
        return False
    cases = evidence.get("cases")
    if not isinstance(cases, list) or len(cases) != 5:
        return False
    labels = {case.get("scenario") for case in cases if isinstance(case, dict)}
    if not {"attack", "normal"}.issubset(labels):
        return False
    replay_pcaps = []
    counts = {"attack": 0, "normal": 0}
    for case in cases:
        if not isinstance(case, dict):
            return False
        if case.get("scenario") not in {"attack", "normal"}:
            return False
        counts[case["scenario"]] += 1
        if not _HEX.fullmatch(case.get("pcap_sha256", "")) or not _HEX.fullmatch(case.get("eve_sha256", "")):
            return False
        if case["pcap_sha256"] == candidate["pcap_sha256"]:
            return False
        replay_pcaps.append(case["pcap_sha256"])
        if type(case.get("events")) is not int or case["events"] <= 0:
            return False
        alerts = case.get("candidate_sid_alerts")
        if type(alerts) is not int or (case["scenario"] == "attack" and alerts < 1) or (case["scenario"] == "normal" and alerts != 0):
            return False
    return counts == {"attack": 2, "normal": 3} and len(replay_pcaps) == len(set(replay_pcaps))
