"""Register an existing, provenance-verified rule artifact for review only.

This adapter connects the existing VM3 handoff artifacts to the lifecycle.
It never approves, copies, installs, reloads, or activates a rule.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from backend.rule_handoff import HandoffError, _read_artifacts
from netids.rule_lifecycle import LifecycleError, RuleLifecycle
from netids.candidate_record import CandidateRecordError, build_candidate_record
from netids.rulegen import collect_sids
from netids.documented_rule_recovery import recover_documented_frozen_rule
from netids.trusted_replay import (
    CAL_SHA, DECISION_SHA, DOCUMENTED_EVIDENCE_GIT_BLOB_SHA,
    DOCUMENTED_EVIDENCE_PATH, DOCUMENTED_EVIDENCE_SHA, EXPECTED_CASES,
    MODEL_SHA, RULE_SHA, SID,
)


def _verified_file(path: Path, expected_sha256: str, label: str) -> tuple[Path, str]:
    resolved = Path(path)
    if resolved.is_symlink() or not resolved.is_file():
        raise LifecycleError(f"Missing or unsafe {label}")
    if (
        not isinstance(expected_sha256, str)
        or len(expected_sha256) != 64
        or any(digit not in "0123456789abcdef" for digit in expected_sha256)
    ):
        raise LifecycleError(f"Missing pinned {label} SHA256")
    actual = hashlib.sha256(resolved.read_bytes()).hexdigest()
    if actual != expected_sha256:
        raise LifecycleError(f"{label} SHA256 mismatch")
    return resolved.resolve(strict=True), actual


def register_generated_candidate(
    *,
    artifact_dir: Path,
    run_id: str,
    calibration_manifest: Path,
    expected_calibration_sha256: str,
    baseline_rules: Path,
    expected_baseline_sha256: str,
    audit_path: Path,
    isolated_root: Path,
    return_private_candidate: bool = False,
    require_candidate_record: bool = False,
) -> dict:
    """Create an immutable-PROPOSED review record from a real generated artifact.

    The source metadata must pass the existing handoff validation. Baseline
    rules and calibration manifests must match owner-pinned hashes; a caller
    cannot silently replace these references with arbitrary new files.
    """
    calibration_path, calibration_sha = _verified_file(
        calibration_manifest, expected_calibration_sha256, "calibration manifest"
    )
    rules_path, baseline_sha = _verified_file(
        baseline_rules, expected_baseline_sha256, "baseline rules"
    )
    try:
        rule_path, metadata_path, rule_text, metadata = _read_artifacts(
            Path(artifact_dir), run_id
        )
    except HandoffError as exc:
        raise LifecycleError("Handoff rule provenance failed") from exc

    for key in ("calibration_sha256", "hybrid_calibration_sha256"):
        if key in metadata and metadata[key] != calibration_sha:
            raise LifecycleError("Generated rule calibration provenance mismatch")

    used_sids = collect_sids(rules_path.read_text(encoding="utf-8").splitlines())
    proposed_sids = collect_sids([rule_text])
    if len(proposed_sids) != 1:
        raise LifecycleError("Rule artifact must contain one SID")
    sid = proposed_sids.pop()

    lifecycle = RuleLifecycle(
        Path(audit_path), isolated_root=Path(isolated_root),
        existing_sids=used_sids,
    )
    source = {
        "run_id": run_id,
        "pcap_sha256": metadata["pcap_sha256"],
        "model_sha256": metadata["model_sha256"],
        "calibration_sha256": calibration_sha,
        "sid": sid,
        "rule": rule_text,
        "rule_sha256": metadata["rule_sha256"],
        "approved": False,
        "deployable": False,
        "deployed": False,
        "source_rule_file_sha256": hashlib.sha256(rule_path.read_bytes()).hexdigest(),
        "source_metadata_sha256": hashlib.sha256(metadata_path.read_bytes()).hexdigest(),
        "calibration_manifest_path": str(calibration_path),
        "baseline_rules_sha256": baseline_sha,
    }
    review_path = Path(artifact_dir) / "review.json"
    if require_candidate_record and not review_path.is_file():
        raise LifecycleError("candidate_record_v1 evidence is required for this acceptance path")
    if review_path.is_file():
        try:
            review = json.loads(review_path.read_text(encoding="utf-8"))
            calibration = json.loads(calibration_path.read_text(encoding="utf-8"))
            if (
                review.get("generated_rule_sid") == sid
                and isinstance(calibration.get("threshold_provenance"), dict)
            ):
                verified = build_candidate_record(
                    Path(artifact_dir), calibration_path, rules_path
                )
                verified.update({
                    "calibration_manifest_path": str(calibration_path),
                    "baseline_rules_sha256": baseline_sha,
                })
                source = verified
            if require_candidate_record is True and source.get("candidate_record_schema") != "candidate_record_v1":
                raise LifecycleError("Candidate record provenance is incomplete")
        except (CandidateRecordError, OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise LifecycleError("Candidate record provenance failed") from exc
    elif require_candidate_record:
        raise LifecycleError("candidate_record_v1 evidence is required for this acceptance path")
    result = lifecycle.create_candidate(source)
    summary = {
        "status": result["state"],
        "candidate_id": result["candidate_id"],
        "run_id": result["run_id"],
        "sid": result["sid"],
        "pcap_sha256": result["pcap_sha256"],
        "model_sha256": result["model_sha256"],
        "calibration_sha256": result["calibration_sha256"],
        "rule_sha256": result["rule_sha256"],
        "source_metadata_sha256": result["source_metadata_sha256"],
        "baseline_rules_sha256": baseline_sha,
        "audit_records": lifecycle.verify_audit(),
        "approved": False,
        "deployable": False,
        "deployed": False,
    }
    if return_private_candidate is True:
        return {"summary": summary, "candidate": result}
    return summary


def register_documented_frozen_candidate(
    *,
    repo_root: Path,
    evidence_path: Path,
    replay_manifest: Path,
    expected_replay_manifest_sha256: str,
    source_pcap: Path,
    calibration_manifest: Path,
    audit_path: Path,
    isolated_root: Path,
    decision_manifest: Path | None = None,
    return_private_candidate: bool = False,
) -> dict:
    """Register the pinned documented rule as a review-only recovery candidate.

    This path intentionally does not read ML worker metadata.  It proves the
    accepted rule came from the pinned Git evidence blob and records that the
    historical RST-generated metadata was not recovered.
    """
    recovered = recover_documented_frozen_rule(
        repo_root=Path(repo_root), evidence_path=Path(evidence_path),
        evidence_git_blob_sha=DOCUMENTED_EVIDENCE_GIT_BLOB_SHA,
        expected_rule_sha256=RULE_SHA, expected_sid=SID,
    )
    provenance = recovered["provenance"]
    if (
        provenance["source_document_path"] != DOCUMENTED_EVIDENCE_PATH
        or provenance["source_document_sha256"] != DOCUMENTED_EVIDENCE_SHA
    ):
        raise LifecycleError("Documented recovery source is not the pinned Git evidence")
    calibration_path, calibration_sha = _verified_file(
        calibration_manifest, CAL_SHA, "frozen calibration manifest"
    )
    if decision_manifest is not None:
        decision_path, decision_sha = _verified_file(
            decision_manifest, DECISION_SHA, "frozen decision manifest"
        )
    else:
        decision_path, decision_sha = None, DECISION_SHA
    pcap_path = Path(source_pcap)
    if pcap_path.is_symlink() or not pcap_path.is_file():
        raise LifecycleError("Source PCAP is missing or unsafe")
    pcap_sha = hashlib.sha256(pcap_path.read_bytes()).hexdigest()
    attack_hashes = {digest for label, digest in EXPECTED_CASES.values() if label == "attack"}
    if pcap_sha not in attack_hashes:
        raise LifecycleError("Source PCAP is not one of the pinned attack holdouts")
    manifest_path, manifest_sha = _verified_file(
        replay_manifest, expected_replay_manifest_sha256, "replay manifest"
    )
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LifecycleError("Replay manifest is not valid JSON") from exc
    if (
        manifest.get("schema_version") != "suricata_replay_manifest_v1"
        or manifest.get("sid") != SID
        or manifest.get("rule_sha256") != RULE_SHA
        or manifest.get("model_sha256") != MODEL_SHA
        or manifest.get("calibration_sha256") != CAL_SHA
        or manifest.get("decision_manifest_sha256") != DECISION_SHA
        or manifest.get("pcap_sha256") != pcap_sha
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", str(manifest.get("run_id", "")))
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", str(manifest.get("replay_run_id", "")))
    ):
        raise LifecycleError("Recovery replay manifest provenance mismatch")
    expected_candidate_id = hashlib.sha256(
        f"{manifest['run_id']}:{SID}:{RULE_SHA}".encode()
    ).hexdigest()
    if manifest.get("candidate_id") != expected_candidate_id:
        raise LifecycleError("Recovery candidate ID is not derived from pinned identity")
    cases = manifest.get("cases")
    if not isinstance(cases, list) or len(cases) != len(EXPECTED_CASES):
        raise LifecycleError("Recovery manifest must contain exactly six pinned cases")
    seen = set()
    for case in cases:
        case_id = case.get("id") if isinstance(case, dict) else None
        if case_id in seen or case_id not in EXPECTED_CASES:
            raise LifecycleError("Recovery manifest contains an unknown or repeated case")
        label, digest = EXPECTED_CASES[case_id]
        if case.get("scenario") != label or case.get("pcap_sha256") != digest:
            raise LifecycleError("Recovery manifest case provenance mismatch")
        seen.add(case_id)
    if seen != set(EXPECTED_CASES):
        raise LifecycleError("Recovery manifest is missing a pinned case")
    source = {
        "run_id": manifest["run_id"], "pcap_sha256": pcap_sha,
        "model_sha256": MODEL_SHA, "calibration_sha256": CAL_SHA,
        "decision_manifest_sha256": DECISION_SHA, "sid": SID,
        "rule": recovered["rule_text"], "rule_sha256": RULE_SHA,
        "approved": False, "deployable": False, "deployed": False,
        "evidence_class": "documented_frozen_rule_recovery",
        "historical_generated_metadata": "unavailable_not_recovered",
        "source_document_path": provenance["source_document_path"],
        "source_document_git_blob_sha256": provenance["source_document_git_blob_sha256"],
        "source_document_sha256": provenance["source_document_sha256"],
        "source_rule_file_sha256": recovered["rule_file_sha256"],
        "source_pcap_path": str(pcap_path.resolve(strict=True)),
        "replay_manifest_path": str(manifest_path),
        "replay_manifest_sha256": manifest_sha,
        "replay_run_id": manifest["replay_run_id"],
        "calibration_manifest_path": str(calibration_path),
        "decision_manifest_path": str(decision_path) if decision_path else None,
        "decision_manifest_sha256": decision_sha,
    }
    lifecycle = RuleLifecycle(Path(audit_path), isolated_root=Path(isolated_root))
    candidate = lifecycle.create_candidate(source)
    summary = {
        "status": candidate["state"], "candidate_id": candidate["candidate_id"],
        "run_id": candidate["run_id"], "sid": candidate["sid"],
        "evidence_class": candidate["evidence_class"],
        "historical_generated_metadata": candidate["historical_generated_metadata"],
        "replay_manifest_sha256": manifest_sha,
        "replay_run_id": manifest["replay_run_id"],
        "approved": False, "deployable": False, "deployed": False,
        "audit_records": lifecycle.verify_audit(),
    }
    return {"summary": summary, "candidate": candidate} if return_private_candidate else summary
