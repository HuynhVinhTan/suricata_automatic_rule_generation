"""Register an existing, provenance-verified rule artifact for review only.

This adapter connects the existing VM3 handoff artifacts to the lifecycle.
It never approves, copies, installs, reloads, or activates a rule.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from backend.rule_handoff import HandoffError, _read_artifacts
from netids.rule_lifecycle import LifecycleError, RuleLifecycle
from netids.rulegen import collect_sids


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
    result = lifecycle.create_candidate(source)
    return {
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
