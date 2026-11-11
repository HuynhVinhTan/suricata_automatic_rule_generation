"""Bounded batch worker for the review-only lab AI pipeline."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import re
import shutil
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from netids.lab_runtime import EXPECTED_MODEL_SHA256, FEATURES, sha256
from netids.pipeline import run as run_pipeline

WORKER_SCHEMA_VERSION = "pcap_ai_worker_v0_1"
MAX_PCAP_SIZE_BYTES = 2 * 1024 * 1024 * 1024
MIN_FREE_DISK_BYTES = 128 * 1024 * 1024
DEFAULT_INPUT_ROOT = Path("data/private/incoming-pcaps")
DEFAULT_ES_INDEX = "suricata-ai-summary"
RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")
REVIEW_STATUS_COMPATIBILITY = {
    "no_candidate": "no_candidate",
    "needs_review": "needs_review",
    "rejected_known_false_positive": "rejected_known_false_positive",
    "rejected_validation_failure": "rejected_validation_failure",
    "validated_for_review": "validated_for_review",
    "NO_CANDIDATE": "no_candidate",
    "NEEDS_REVIEW": "needs_review",
    "REJECTED_KNOWN_FALSE_POSITIVE": "rejected_known_false_positive",
    "REJECTED_VALIDATION_FAILURE": "rejected_validation_failure",
    "VALIDATED_FOR_REVIEW": "validated_for_review",
}


class WorkerProcessingError(RuntimeError):
    """A pipeline output was incomplete or violated the review contract."""


class ElasticsearchWriteError(RuntimeError):
    """Elasticsearch rejected or could not confirm an AI summary write."""


class ElasticsearchConnectionError(ElasticsearchWriteError):
    """The Elasticsearch endpoint could not be reached."""


class ElasticsearchConflictError(ElasticsearchWriteError):
    """The stable AI document ID already exists."""


def sha256_file(path: Path) -> str:
    return sha256(path)


def normalize_ipv4(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be an IPv4 string")
    try:
        return str(IPv4Address(value))
    except ValueError as exc:
        raise ValueError(f"Invalid IPv4 for {field_name}") from exc


def validate_run_id(value: Any) -> str:
    if not isinstance(value, str) or not RUN_ID_PATTERN.fullmatch(value):
        raise ValueError("Invalid run ID; use 1-64 letters, digits, '_' or '-'")
    return value


def normalize_review_status(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("Review status must be a string")
    status = REVIEW_STATUS_COMPATIBILITY.get(value)
    if status is None:
        raise ValueError(f"Unsupported review status: {value}")
    return status


def load_manifest(path: Path) -> Dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as stream:
        manifest = json.load(stream)
    if not isinstance(manifest, dict):
        raise ValueError("Manifest must be a JSON object")
    return manifest


def validate_manifest(
    manifest: Mapping[str, Any],
    *,
    pcap_path: Path,
    src: str,
    dst: str,
    run_id: str,
) -> Dict[str, Any]:
    if not isinstance(manifest, Mapping):
        raise ValueError("Manifest must be a JSON object")
    if manifest.get("schema_version") != WORKER_SCHEMA_VERSION:
        raise ValueError("Unsupported manifest schema_version")

    required = {
        "pcap_sha256",
        "source_ipv4",
        "destination_ipv4",
        "run_id",
    }
    missing = required - set(manifest)
    if missing:
        raise ValueError(f"Manifest missing required fields: {sorted(missing)}")

    manifest_run_id = validate_run_id(manifest["run_id"])
    if manifest_run_id != run_id:
        raise ValueError("Manifest run_id does not match the requested run")
    if not isinstance(manifest["pcap_sha256"], str) or not SHA256_PATTERN.fullmatch(
        manifest["pcap_sha256"]
    ):
        raise ValueError("Manifest must contain a valid PCAP SHA256")
    if sha256_file(pcap_path).lower() != manifest["pcap_sha256"].lower():
        raise ValueError("Manifest PCAP SHA256 does not match the input file")
    if normalize_ipv4(manifest["source_ipv4"], "source_ipv4") != normalize_ipv4(
        src, "source_ipv4"
    ):
        raise ValueError("Manifest source IPv4 does not match the worker input")
    if normalize_ipv4(
        manifest["destination_ipv4"], "destination_ipv4"
    ) != normalize_ipv4(dst, "destination_ipv4"):
        raise ValueError("Manifest destination IPv4 does not match the worker input")

    metadata = manifest.get("capture_metadata", {})
    if not isinstance(metadata, dict):
        raise ValueError("Manifest capture_metadata must be an object")
    return dict(manifest)


def _require_under(path: Path, root: Path, description: str) -> Path:
    try:
        resolved_root = root.resolve(strict=True)
        resolved_path = path.resolve(strict=True)
        resolved_path.relative_to(resolved_root)
    except (OSError, ValueError) as exc:
        raise ValueError(f"{description} must be inside the allowlisted root") from exc
    return resolved_path


def _safe_artifact(root: Path, relative: Path) -> Path:
    path = root / relative
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise FileNotFoundError(f"Required private artifact missing or unsafe: {relative}") from exc
    if not resolved.is_file():
        raise FileNotFoundError(f"Required private artifact is not a file: {relative}")
    return resolved


def preflight_artifacts(private_root: Path) -> Dict[str, str]:
    root = Path(private_root).resolve(strict=True)
    model_path = _safe_artifact(
        root, Path("lab-models/lab_syn_anomaly_v0_1/models.joblib")
    )
    report_path = _safe_artifact(
        root, Path("lab-models/lab_syn_anomaly_v0_1/report.json")
    )
    proposal_path = _safe_artifact(
        root, Path("lab-rule-candidates/syn_scan_v0_1/proposal.json")
    )
    candidate_path = _safe_artifact(
        root, Path("lab-rule-candidates/syn_scan_v0_1/candidate.rules")
    )

    report = json.loads(report_path.read_text(encoding="utf-8"))
    if (
        report.get("experiment") != "lab_syn_anomaly_v0_1"
        or report.get("training_policy") != "NORMAL_ONLY"
        or report.get("feature_names") != FEATURES
        or report.get("window_seconds") != 10
    ):
        raise ValueError("Frozen model report contract mismatch")
    thresholds = report.get("thresholds")
    if not isinstance(thresholds, dict) or any(
        name not in thresholds
        or isinstance(thresholds[name], bool)
        or not isinstance(thresholds[name], (int, float))
        or not math.isfinite(float(thresholds[name]))
        for name in ("IsolationForest", "NumpyAutoencoder")
    ):
        raise ValueError("Frozen model report thresholds are invalid")
    if sha256_file(model_path) != EXPECTED_MODEL_SHA256:
        raise ValueError("Frozen model SHA256 mismatch")

    reference_hashes = report.get("feature_csv_sha256")
    if not isinstance(reference_hashes, dict):
        raise ValueError("Frozen model report has no reference checksums")
    reference_hashes_checked = {}
    for partition in ("normal-train", "normal-cal"):
        relative = Path(
            "lab-sessions/normal-batch-v01"
            f"/syn_windows_10s_{partition}.csv"
        )
        reference_path = _safe_artifact(root, relative)
        expected_hash = reference_hashes.get(partition)
        if not isinstance(expected_hash, str) or not SHA256_PATTERN.fullmatch(
            expected_hash
        ):
            raise ValueError(f"Frozen report lacks {partition} checksum")
        actual_hash = sha256_file(reference_path)
        if actual_hash != expected_hash.lower():
            raise ValueError(f"Normal reference checksum mismatch: {partition}")
        if reference_path.stat().st_size == 0:
            raise ValueError(f"Normal reference is empty: {partition}")
        with reference_path.open(
            "r", encoding="utf-8", newline=""
        ) as stream:
            reader = csv.DictReader(stream)
            required_columns = {"label", "window_seconds", "syn_count"}
            if not required_columns.issubset(reader.fieldnames or []):
                raise ValueError(f"Normal reference schema mismatch: {partition}")
            rows = list(reader)
        if not rows:
            raise ValueError(f"Normal reference has no rows: {partition}")
        for row in rows:
            try:
                valid_row = (
                    row["label"] == "NORMAL"
                    and int(row["window_seconds"]) == 10
                    and int(row["syn_count"]) >= 1
                )
            except (TypeError, ValueError):
                valid_row = False
            if not valid_row:
                raise ValueError(f"Invalid Normal reference row: {partition}")
        reference_hashes_checked[partition] = actual_hash

    proposal = json.loads(proposal_path.read_text(encoding="utf-8-sig"))
    if (
        proposal.get("status") != "needs_review"
        or proposal.get("deployed") is not False
        or proposal.get("model_report_sha256") != sha256_file(report_path)
    ):
        raise ValueError("Historical rule proposal provenance mismatch")
    candidate_rule = candidate_path.read_text(encoding="utf-8")
    if "sid:9102001;" not in candidate_rule or "192.168.10.10" not in candidate_rule:
        raise ValueError("Historical rule candidate SID mismatch")

    return {
        "model_sha256": sha256_file(model_path),
        "model_report_sha256": sha256_file(report_path),
        "normal_train_sha256": reference_hashes_checked["normal-train"],
        "normal_cal_sha256": reference_hashes_checked["normal-cal"],
        "historical_proposal_sha256": sha256_file(proposal_path),
    }


def _review_is_safe(review: Mapping[str, Any]) -> str:
    """Validate the deny-by-default safety contract for each review schema.

    v0_2 requires top-level ``approved``; historical v0_1 producers did not
    emit it, but both versions require false deployment claims and nested
    triage/candidate-gate safety fields.
    """
    schema_version = review.get("schema_version")
    if schema_version not in {
        "lab_rule_review_v0_1",
        "lab_rule_review_v0_2",
    }:
        raise WorkerProcessingError("Unsupported review artifact schema")
    status = normalize_review_status(review.get("status"))

    required_top_level = ("deployable", "deployed")
    if schema_version == "lab_rule_review_v0_2":
        required_top_level = ("approved", *required_top_level)
    for key in required_top_level:
        if key not in review:
            raise WorkerProcessingError(
                f"Review artifact is missing mandatory field: {key}"
            )
        if review[key] is not False:
            raise WorkerProcessingError(
                f"Review artifact field {key} must be boolean false"
            )

    for key in (
        "approved",
        "auto_approve",
        "auto_deploy",
        "rule_approval_authorized",
    ):
        if key in review and review[key] is not False:
            raise WorkerProcessingError(
                f"Review artifact field {key} must be boolean false"
            )

    triage = review.get("triage")
    if not isinstance(triage, dict):
        raise WorkerProcessingError("Review artifact triage must be an object")
    for key in ("auto_approve", "auto_deploy"):
        if key not in triage:
            raise WorkerProcessingError(
                f"Review artifact triage is missing mandatory field: {key}"
            )
        if triage[key] is not False:
            raise WorkerProcessingError(
                f"Review artifact triage field {key} must be boolean false"
            )

    candidate_gate = review.get("candidate_gate")
    if not isinstance(candidate_gate, dict):
        raise WorkerProcessingError(
            "Review artifact candidate_gate must be an object"
        )
    key = "rule_approval_authorized"
    if key not in candidate_gate:
        raise WorkerProcessingError(
            f"Review artifact candidate_gate is missing mandatory field: {key}"
        )
    if candidate_gate[key] is not False:
        raise WorkerProcessingError(
            f"Review artifact candidate_gate field {key} must be boolean false"
        )

    hybrid = review.get("hybrid_review")
    if hybrid is not None:
        if not isinstance(hybrid, dict) or hybrid.get("schema_version") != "hybrid_review_v1":
            raise WorkerProcessingError("Review artifact hybrid review is malformed")
        for field in ("approved", "deployable", "deployed", "suricata_signature_equivalent"):
            if hybrid.get(field) is not False:
                raise WorkerProcessingError(
                    f"Review artifact hybrid {field} must be boolean false"
                )
        if hybrid.get("requires_manual_review") is not True or hybrid.get("python_only") is not True:
            raise WorkerProcessingError("Review artifact hybrid safety contract is invalid")
        provenance = hybrid.get("calibration_provenance")
        if not isinstance(provenance, dict) or provenance.get("status") not in {"accepted", "rejected"}:
            raise WorkerProcessingError("Review artifact hybrid calibration provenance is invalid")
    return status


def _validate_generated_rule_artifacts(
    output_dir: Path,
    review: Mapping[str, Any],
    *,
    run_id: str,
    pcap_sha256: str,
    model_sha256: str,
) -> None:
    """Validate the generated rule as a review-only, provenance-bound pair."""
    rule_path = output_dir / "ml-generated.rules"
    metadata_path = output_dir / "ml-generated.metadata.json"
    generated = review.get("rule_generated_in_this_run") is True

    if not generated:
        if rule_path.exists() or metadata_path.exists():
            raise WorkerProcessingError(
                "Rule artifacts exist without a generated-rule review claim"
            )
        return

    try:
        if rule_path.is_symlink() or metadata_path.is_symlink():
            raise WorkerProcessingError("Generated rule artifacts must not be symlinks")
        rule_text_with_newline = rule_path.read_text(encoding="utf-8")
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise WorkerProcessingError(
            "Generated rule artifacts are missing or invalid"
        ) from exc

    if not isinstance(metadata, dict) or not rule_text_with_newline.endswith("\n"):
        raise WorkerProcessingError("Generated rule artifacts are malformed")
    rule_text = rule_text_with_newline[:-1]
    expected_rule_sha = hashlib.sha256(rule_text.encode("utf-8")).hexdigest()
    if (
        metadata.get("schema_version") != "ml_rule_metadata_v1"
        or metadata.get("run_id") != run_id
        or metadata.get("pcap_sha256") != pcap_sha256.lower()
        or metadata.get("model_sha256") != model_sha256
        or metadata.get("rule_sha256") != expected_rule_sha
        or metadata.get("status")
        not in {"needs_review", "rejected_validation_failure"}
        or any(metadata.get(field) is not False for field in ("approved", "deployable", "deployed"))
        or review.get("generated_rule") != rule_text
        or metadata.get("status") != review.get("status")
        or review.get("generated_rule_sid") is None
        or review.get("generated_rule_metadata", {}).get("rule_sha256") != expected_rule_sha
    ):
        raise WorkerProcessingError("Generated rule provenance or review-only safety mismatch")

    sids = [int(value) for value in re.findall(r"\bsid:(\d+);", rule_text)]
    if len(sids) != 1 or sids[0] != review["generated_rule_sid"] or sids[0] in {9102001, 9102002}:
        raise WorkerProcessingError("Generated rule SID is invalid or rejected")


def _require_provenance_sha256(
    artifact: Mapping[str, Any], field: str, expected: str, name: str
) -> None:
    value = artifact.get(field)
    if (
        not isinstance(value, str)
        or not SHA256_PATTERN.fullmatch(value)
        or value.lower() != expected.lower()
    ):
        raise WorkerProcessingError(
            f"{name} {field} provenance is missing, invalid, or mismatched"
        )


def _write_json_exclusive(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(payload, stream, indent=2, ensure_ascii=False)
        stream.write("\n")


def _private_directory(root: Path, name: str) -> Path:
    requested = root / name
    requested.mkdir(parents=True, exist_ok=True)
    resolved = requested.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"Private output directory escapes private_root: {name}") from exc
    if not resolved.is_dir():
        raise NotADirectoryError(f"Private output path is not a directory: {name}")
    return resolved


def _failure_payload(
    *, run_id: str, pcap_sha256: str, exc: BaseException
) -> Dict[str, Any]:
    return {
        "schema_version": WORKER_SCHEMA_VERSION,
        "run_id": run_id,
        "pcap_sha256": pcap_sha256,
        "status": "failed",
        "error_type": type(exc).__name__,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "deployable": False,
        "deployed": False,
    }


def _record_output_failure(
    output_dir: Path, run_id: str, expected_sha: str, error: BaseException
) -> None:
    _write_failure_without_masking(
        output_dir / "worker_summary.json",
        _failure_payload(
            run_id=run_id, pcap_sha256=expected_sha, exc=error
        ),
        error,
    )


def _write_failure_without_masking(
    path: Path, payload: Mapping[str, Any], original: BaseException
) -> None:
    try:
        _write_json_exclusive(path, payload)
    except OSError as artifact_error:
        note = f"Could not write failure artifact: {type(artifact_error).__name__}"
        if hasattr(original, "add_note"):
            original.add_note(note)
        else:
            setattr(original, "failure_artifact_error", note)


def _safe_summary_fields(summary: Mapping[str, Any]) -> Dict[str, Any]:
    if summary.get("schema_version") != WORKER_SCHEMA_VERSION:
        raise ValueError("Unsupported Elasticsearch summary schema")
    if summary.get("status") != "succeeded":
        raise ValueError("Only succeeded worker summaries may be published")
    validate_run_id(summary.get("run_id"))
    required = {
        "review_status",
        "pcap_sha256",
        "model_sha256",
        "generated_at",
        "rule_generated_in_this_run",
        "deployable",
        "deployed",
        "windows",
        "isolation_forest_flagged",
        "autoencoder_flagged",
        "both_flagged",
    }
    missing = required - set(summary)
    if missing:
        raise ValueError(
            f"Elasticsearch summary is missing required fields: {sorted(missing)}"
        )
    normalize_review_status(summary["review_status"])
    for key in ("pcap_sha256", "model_sha256"):
        if not isinstance(summary[key], str) or not SHA256_PATTERN.fullmatch(
            summary[key]
        ):
            raise ValueError(f"Invalid {key} in Elasticsearch summary")
    for key in (
        "windows",
        "isolation_forest_flagged",
        "autoencoder_flagged",
        "both_flagged",
    ):
        if type(summary[key]) is not int or summary[key] < 0:
            raise ValueError(f"Invalid {key} in Elasticsearch summary")
    if (
        summary["windows"] < 1
        or any(
            summary[name] > summary["windows"]
            for name in (
                "isolation_forest_flagged",
                "autoencoder_flagged",
                "both_flagged",
            )
        )
        or summary["both_flagged"]
        > min(
            summary["isolation_forest_flagged"],
            summary["autoencoder_flagged"],
        )
    ):
        raise ValueError("Invalid prediction counts in Elasticsearch summary")
    generated_at = summary.get("generated_at")
    if not isinstance(generated_at, str) or len(generated_at) > 64:
        raise ValueError("Invalid generated_at in Elasticsearch summary")
    try:
        generated = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
        if generated.utcoffset() is None:
            raise ValueError("generated_at must include a timezone")
    except ValueError as exc:
        raise ValueError(
            "Invalid generated_at in Elasticsearch summary"
        ) from exc
    for key in ("deployable", "deployed"):
        if summary[key] is not False:
            raise ValueError("Refusing to publish an approved or deployed rule claim")
    if type(summary["rule_generated_in_this_run"]) is not bool:
        raise ValueError("Invalid rule_generated_in_this_run in Elasticsearch summary")
    allowed = (
        "schema_version",
        "run_id",
        "status",
        "review_status",
        "pcap_sha256",
        "model_sha256",
        "generated_at",
        "windows",
        "isolation_forest_flagged",
        "autoencoder_flagged",
        "both_flagged",
        "rule_generated_in_this_run",
        "deployable",
        "deployed",
    )
    safe = {key: summary[key] for key in allowed if key in summary}
    if "review_status" in safe:
        safe["review_status"] = normalize_review_status(safe["review_status"])
    return safe


def verify_completed_run(
    private_root: Path, run_id: str, pcap_sha256: str
) -> Dict[str, Any]:
    """Validate persisted worker output before recovery or receipt creation."""
    run_id = validate_run_id(run_id)
    if not isinstance(pcap_sha256, str) or not SHA256_PATTERN.fullmatch(
        pcap_sha256
    ):
        raise WorkerProcessingError("Invalid expected PCAP checksum")
    root = Path(private_root).resolve(strict=True)
    run_root = root / "lab-runs"
    output_dir = run_root / run_id
    if run_root.is_symlink() or output_dir.is_symlink():
        raise WorkerProcessingError("Completed run output must not use symlinks")
    try:
        output_dir.resolve(strict=True).relative_to(root)
    except (OSError, ValueError) as exc:
        raise WorkerProcessingError(
            "Completed run output is missing or outside private_root"
        ) from exc
    if not output_dir.is_dir():
        raise WorkerProcessingError("Completed run output is not a directory")

    def read_artifact(relative: str) -> Dict[str, Any]:
        path = output_dir / relative
        if path.is_symlink():
            raise WorkerProcessingError(
                f"Completed run artifact must not be a symlink: {relative}"
            )
        try:
            _safe_artifact(output_dir, Path(relative))
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise WorkerProcessingError(
                f"Completed run artifact is missing or invalid: {relative}"
            ) from exc
        if not isinstance(value, dict):
            raise WorkerProcessingError(
                f"Completed run artifact must be an object: {relative}"
            )
        return value

    summary = read_artifact("worker_summary.json")
    review = read_artifact("review.json")
    predictions = read_artifact("predictions.json")
    feature_path = output_dir / "syn_windows.csv"
    if feature_path.is_symlink():
        raise WorkerProcessingError(
            "Completed run feature artifact must not be a symlink"
        )
    try:
        _safe_artifact(output_dir, Path("syn_windows.csv"))
        feature_sha256 = sha256_file(feature_path)
        artifacts = preflight_artifacts(root)
        safe_summary = _safe_summary_fields(summary)
    except (OSError, ValueError) as exc:
        raise WorkerProcessingError(
            "Completed run provenance or frozen artifact validation failed"
        ) from exc

    generated_at = summary.get("generated_at")
    if (
        summary.get("schema_version") != WORKER_SCHEMA_VERSION
        or summary.get("run_id") != run_id
        or summary.get("status") != "succeeded"
        or summary.get("pcap_sha256", "").lower() != pcap_sha256.lower()
        or summary.get("model_sha256") != artifacts["model_sha256"]
        or not isinstance(generated_at, str)
        or summary.get("deployable") is not False
        or summary.get("deployed") is not False
        or type(summary.get("rule_generated_in_this_run")) is not bool
    ):
        raise WorkerProcessingError(
            "Completed worker summary identity or review-only safety fields mismatch"
        )
    try:
        review_status = _review_is_safe(review)
    except WorkerProcessingError:
        raise
    if (
        review_status != summary.get("review_status")
        or summary.get("rule_generated_in_this_run")
        is not (review.get("rule_generated_in_this_run") is True)
    ):
        raise WorkerProcessingError(
            "Completed worker summary does not match the review artifact"
        )
    _validate_generated_rule_artifacts(
        output_dir,
        review,
        run_id=run_id,
        pcap_sha256=pcap_sha256,
        model_sha256=artifacts["model_sha256"],
    )
    try:
        generated = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
        if generated.utcoffset() is None:
            raise ValueError
    except ValueError as exc:
        raise WorkerProcessingError(
            "Completed worker summary timestamp is invalid"
        ) from exc
    _require_provenance_sha256(
        review, "source_pcap_sha256", pcap_sha256, "Review"
    )
    _require_provenance_sha256(
        review, "feature_csv_sha256", feature_sha256, "Review"
    )
    _require_provenance_sha256(
        predictions, "input_sha256", feature_sha256, "Prediction"
    )
    if (
        review.get("model_sha256") != artifacts["model_sha256"]
        or predictions.get("model_sha256") != artifacts["model_sha256"]
    ):
        raise WorkerProcessingError(
            "Completed run model provenance does not match the frozen model"
        )
    for field in (
        "training_performed",
        "suricata_rule_generated",
        "rule_deployed",
    ):
        if predictions.get(field) is not False:
            raise WorkerProcessingError(
                f"Completed run prediction {field} must be boolean false"
            )
    metric_names = (
        "windows",
        "isolation_forest_flagged",
        "autoencoder_flagged",
        "both_flagged",
    )
    metrics = {name: predictions.get(name) for name in metric_names}
    if (
        any(type(value) is not int or value < 0 for value in metrics.values())
        or metrics["windows"] < 1
        or any(metrics[name] > metrics["windows"] for name in metric_names[1:])
        or metrics["both_flagged"]
        > min(metrics["isolation_forest_flagged"], metrics["autoencoder_flagged"])
        or any(summary.get(name) != value for name, value in metrics.items())
    ):
        raise WorkerProcessingError(
            "Completed run prediction counts do not match the summary"
        )
    return safe_summary


def write_elasticsearch_summary(
    summary: Mapping[str, Any],
    base_url: str,
    *,
    index: str = DEFAULT_ES_INDEX,
    timeout: float = 5.0,
) -> Dict[str, Any]:
    if timeout <= 0:
        raise ValueError("Elasticsearch timeout must be positive")
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,254}", index):
        raise ValueError("Invalid Elasticsearch index name")
    parsed = urllib.parse.urlsplit(base_url)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Elasticsearch URL must be an HTTP(S) base URL without credentials")

    safe_document = _safe_summary_fields(summary)
    document_id = hashlib.sha256(
        summary["run_id"].encode("utf-8")
    ).hexdigest()
    document_endpoint = (
        base_url.rstrip("/")
        + "/"
        + urllib.parse.quote(index, safe="")
        + "/_doc/"
        + document_id
    )
    endpoint = document_endpoint + "?op_type=create"
    request = urllib.request.Request(
        endpoint,
        data=json.dumps(safe_document, sort_keys=True).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="PUT",
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if not 200 <= response.status < 300:
                raise ElasticsearchWriteError(
                    f"Elasticsearch returned HTTP {response.status}"
                )
            response.read()
    except urllib.error.HTTPError as exc:
        if exc.code == 409:
            get_request = urllib.request.Request(
                document_endpoint, headers={"Accept": "application/json"},
                method="GET",
            )
            try:
                with urllib.request.urlopen(get_request, timeout=timeout) as response:
                    if not 200 <= response.status < 300:
                        raise ElasticsearchConflictError(
                            "Elasticsearch conflict could not be verified"
                        )
                    existing = json.loads(response.read())
            except ElasticsearchConflictError:
                raise
            except urllib.error.HTTPError as get_error:
                raise ElasticsearchConflictError(
                    f"Elasticsearch conflict verification returned HTTP {get_error.code}"
                ) from get_error
            except (urllib.error.URLError, TimeoutError, OSError) as get_error:
                raise ElasticsearchConnectionError(
                    "Elasticsearch conflict verification request failed"
                ) from get_error
            except (ValueError, TypeError) as get_error:
                raise ElasticsearchConflictError(
                    "Elasticsearch conflict response was invalid"
                ) from get_error
            existing_source = existing.get("_source") if isinstance(
                existing, dict
            ) else None
            try:
                source_matches = (
                    isinstance(existing_source, dict)
                    and json.dumps(
                        existing_source,
                        sort_keys=True,
                        separators=(",", ":"),
                        allow_nan=False,
                    )
                    == json.dumps(
                        safe_document,
                        sort_keys=True,
                        separators=(",", ":"),
                        allow_nan=False,
                    )
                )
            except (TypeError, ValueError):
                source_matches = False
            if (
                not isinstance(existing, dict)
                or existing.get("found") is not True
                or existing.get("_id") != document_id
                or existing.get("_index") != index
                or not source_matches
            ):
                raise ElasticsearchConflictError(
                    "Elasticsearch document exists but does not exactly match"
                )
            return {
                "document_id": document_id,
                "index": index,
                "status": "already_exists",
            }
        raise ElasticsearchWriteError(
            f"Elasticsearch returned HTTP {exc.code}"
        ) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ElasticsearchConnectionError(
            "Elasticsearch connection failed"
        ) from exc

    return {"document_id": document_id, "index": index, "status": "created"}


def run_worker(
    *,
    pcap: Path,
    input_root: Path,
    src: str,
    dst: str,
    private_root: Path,
    run_id: str,
    expected_sha: Optional[str] = None,
    manifest_path: Optional[Path] = None,
    output_dir: Optional[Path] = None,
    processor: Optional[Any] = None,
) -> Dict[str, Any]:
    run_id = validate_run_id(run_id)
    src = normalize_ipv4(src, "source_ipv4")
    dst = normalize_ipv4(dst, "destination_ipv4")
    if src == dst:
        raise ValueError("Source and destination IPv4 addresses must differ")

    input_root = Path(input_root)
    try:
        resolved_input_root = input_root.resolve(strict=True)
    except OSError as exc:
        raise FileNotFoundError("Allowlisted PCAP input root does not exist") from exc
    if resolved_input_root.parent == resolved_input_root:
        raise ValueError("Allowlisted PCAP input root cannot be a filesystem root")
    if not resolved_input_root.is_dir():
        raise ValueError("Allowlisted PCAP input root must be a directory")
    pcap = _require_under(Path(pcap), resolved_input_root, "PCAP input")
    if not pcap.is_file():
        raise ValueError("PCAP input must be a regular file")
    size = pcap.stat().st_size
    if size > MAX_PCAP_SIZE_BYTES:
        raise ValueError("PCAP exceeds the safe local prototype size limit")

    private_root = Path(private_root).resolve(strict=True)
    if private_root.parent == private_root:
        raise ValueError("private_root cannot be a filesystem root")
    if not private_root.is_dir():
        raise NotADirectoryError("private_root must be a directory")
    required_free = max(MIN_FREE_DISK_BYTES, size * 2 + 64 * 1024 * 1024)
    if shutil.disk_usage(private_root).free < required_free:
        raise OSError("Insufficient disk space for bounded PCAP processing")

    run_root = private_root / "lab-runs"
    canonical_run_root = run_root.resolve()
    try:
        canonical_run_root.relative_to(private_root)
    except ValueError as exc:
        raise ValueError("Run output root escapes private_root") from exc
    canonical_output = canonical_run_root / run_id
    if output_dir is not None:
        requested_output = Path(output_dir)
        if requested_output.resolve() != canonical_output.resolve():
            raise ValueError("Output directory must be the deterministic run path")
    output_dir = canonical_output
    failure_root = _private_directory(private_root, "lab-failures")
    failure_path = failure_root / f"{run_id}.json"
    if output_dir.exists() or failure_path.exists():
        raise FileExistsError("Run ID already has output; refusing overwrite")

    if expected_sha is not None:
        if not isinstance(expected_sha, str) or not SHA256_PATTERN.fullmatch(
            expected_sha
        ):
            raise ValueError("Expected PCAP SHA256 must be 64 hexadecimal characters")
        expected_sha = expected_sha.lower()

    manifest = None
    if manifest_path is not None:
        manifest_file = Path(manifest_path)
        if not manifest_file.exists():
            raise FileNotFoundError("Manifest file does not exist")
        manifest_file = _require_under(
            manifest_file, resolved_input_root, "Manifest"
        )
        manifest = validate_manifest(
            load_manifest(manifest_file),
            pcap_path=pcap,
            src=src,
            dst=dst,
            run_id=run_id,
        )
    if expected_sha is None and manifest is None:
        raise ValueError("Provide a trusted PCAP checksum or a validated manifest")

    actual_sha = sha256_file(pcap)
    if expected_sha is not None and actual_sha != expected_sha:
        raise ValueError("Input PCAP SHA256 mismatch")
    if manifest is not None and actual_sha != manifest["pcap_sha256"].lower():
        raise ValueError("Manifest PCAP SHA256 mismatch")
    expected_sha = expected_sha or manifest["pcap_sha256"].lower()

    lock_root = _private_directory(private_root, ".worker-locks")
    lock_path = lock_root / f"{run_id}.lock"
    try:
        descriptor = os.open(
            str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY
        )
    except FileExistsError as exc:
        raise FileExistsError("Run ID is already being processed") from exc

    processor_fn = processor or run_pipeline
    try:
        try:
            artifacts = preflight_artifacts(private_root)
            if processor is None:
                run_pipeline(
                    pcap,
                    expected_sha,
                    src,
                    dst,
                    private_root,
                    output_dir,
                    capture_metadata=(manifest or {}).get("capture_metadata", {}),
                )
            else:
                processor_fn(
                    pcap,
                    expected_sha,
                    src,
                    dst,
                    private_root,
                    output_dir,
                )
        except Exception as exc:
            failure = _failure_payload(
                run_id=run_id, pcap_sha256=expected_sha, exc=exc
            )
            try:
                safe_output = output_dir.resolve(strict=True)
                safe_output.relative_to(private_root)
            except (OSError, ValueError):
                safe_output = None
            if safe_output is not None and safe_output.is_dir():
                _write_failure_without_masking(
                    safe_output / "worker_summary.json", failure, exc
                )
            else:
                _write_failure_without_masking(failure_path, failure, exc)
            raise

        try:
            output_dir.resolve(strict=True).relative_to(private_root)
        except (OSError, ValueError) as exc:
            failure = WorkerProcessingError(
                "Pipeline output directory escaped private_root"
            )
            _write_failure_without_masking(
                failure_path,
                _failure_payload(
                    run_id=run_id,
                    pcap_sha256=expected_sha,
                    exc=failure,
                ),
                failure,
            )
            raise failure from exc

        review_path = output_dir / "review.json"
        try:
            with review_path.open("r", encoding="utf-8") as stream:
                review = json.load(stream)
        except (OSError, json.JSONDecodeError) as exc:
            failure = WorkerProcessingError(
                "Pipeline did not produce a valid review artifact"
            )
            _record_output_failure(output_dir, run_id, expected_sha, failure)
            raise failure from exc
        if not isinstance(review, dict):
            failure = WorkerProcessingError(
                "Pipeline review artifact must be a JSON object"
            )
            _record_output_failure(output_dir, run_id, expected_sha, failure)
            raise failure

        try:
            review_status = _review_is_safe(review)
        except WorkerProcessingError as exc:
            _record_output_failure(output_dir, run_id, expected_sha, exc)
            raise

        try:
            feature_path = _safe_artifact(
                output_dir, Path("syn_windows.csv")
            )
            feature_sha256 = sha256_file(feature_path)
            _require_provenance_sha256(
                review,
                "source_pcap_sha256",
                expected_sha,
                "Review",
            )
            _require_provenance_sha256(
                review,
                "feature_csv_sha256",
                feature_sha256,
                "Review",
            )
        except WorkerProcessingError as exc:
            _record_output_failure(output_dir, run_id, expected_sha, exc)
            raise
        except (OSError, ValueError) as exc:
            failure = WorkerProcessingError(
                "Pipeline did not produce a valid feature CSV for provenance"
            )
            _record_output_failure(output_dir, run_id, expected_sha, failure)
            raise failure from exc

        if review.get("model_sha256") != artifacts["model_sha256"]:
            failure = WorkerProcessingError(
                "Review model checksum does not match frozen preflight model"
            )
            _record_output_failure(output_dir, run_id, expected_sha, failure)
            raise failure

        try:
            _validate_generated_rule_artifacts(
                output_dir,
                review,
                run_id=run_id,
                pcap_sha256=expected_sha,
                model_sha256=artifacts["model_sha256"],
            )
        except WorkerProcessingError as exc:
            _record_output_failure(output_dir, run_id, expected_sha, exc)
            raise

        predictions_path = output_dir / "predictions.json"
        try:
            inference = json.loads(
                predictions_path.read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError) as exc:
            failure = WorkerProcessingError(
                "Pipeline did not produce valid predictions"
            )
            _record_output_failure(output_dir, run_id, expected_sha, failure)
            raise failure from exc
        if not isinstance(inference, dict):
            failure = WorkerProcessingError(
                "Pipeline predictions must be a JSON object"
            )
            _record_output_failure(output_dir, run_id, expected_sha, failure)
            raise failure
        try:
            _require_provenance_sha256(
                inference,
                "input_sha256",
                feature_sha256,
                "Prediction",
            )
            for field in (
                "training_performed",
                "suricata_rule_generated",
                "rule_deployed",
            ):
                if inference.get(field) is not False:
                    raise WorkerProcessingError(
                        f"Prediction {field} metadata must be boolean false"
                    )
        except WorkerProcessingError as exc:
            _record_output_failure(output_dir, run_id, expected_sha, exc)
            raise
        if inference.get("model_sha256") != artifacts["model_sha256"]:
            failure = WorkerProcessingError(
                "Prediction model checksum does not match frozen preflight model"
            )
            _record_output_failure(output_dir, run_id, expected_sha, failure)
            raise failure
        metric_names = (
            "windows",
            "isolation_forest_flagged",
            "autoencoder_flagged",
            "both_flagged",
        )
        metrics = {name: inference.get(name) for name in metric_names}
        if any(
            type(value) is not int or value < 0
            for value in metrics.values()
        ) or metrics["windows"] < 1 or any(
            metrics[name] > metrics["windows"]
            for name in metric_names[1:]
        ):
            failure = WorkerProcessingError(
                "Pipeline prediction counts are invalid"
            )
            _record_output_failure(output_dir, run_id, expected_sha, failure)
            raise failure
        if metrics["both_flagged"] > min(
            metrics["isolation_forest_flagged"],
            metrics["autoencoder_flagged"],
        ):
            failure = WorkerProcessingError(
                "Pipeline consensus count exceeds model anomaly counts"
            )
            _record_output_failure(output_dir, run_id, expected_sha, failure)
            raise failure
        result = {
            "schema_version": WORKER_SCHEMA_VERSION,
            "run_id": run_id,
            "pcap_sha256": expected_sha,
            "model_sha256": artifacts["model_sha256"],
            "status": "succeeded",
            "review_status": review_status,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            **metrics,
            "rule_generated_in_this_run": review.get(
                "rule_generated_in_this_run"
            )
            is True,
            "deployable": False,
            "deployed": False,
        }
        _write_json_exclusive(output_dir / "worker_summary.json", result)
        return result
    finally:
        os.close(descriptor)
        lock_path.unlink(missing_ok=True)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--input-root", type=Path, default=DEFAULT_INPUT_ROOT)
    parser.add_argument("--src", required=True)
    parser.add_argument("--dst", required=True)
    parser.add_argument("--private-root", type=Path, default=Path("data/private"))
    parser.add_argument("--run-id", required=True)
    checksum = parser.add_mutually_exclusive_group()
    checksum.add_argument("--expected-sha256")
    checksum.add_argument("--manifest", type=Path)
    parser.add_argument("--elasticsearch-url")
    args = parser.parse_args(argv)

    try:
        summary = run_worker(
            pcap=args.pcap,
            input_root=args.input_root,
            src=args.src,
            dst=args.dst,
            private_root=args.private_root,
            run_id=args.run_id,
            expected_sha=args.expected_sha256,
            manifest_path=args.manifest,
        )
        if args.elasticsearch_url:
            write_elasticsearch_summary(summary, args.elasticsearch_url)
    except Exception as exc:
        print(
            json.dumps({
                "schema_version": WORKER_SCHEMA_VERSION,
                "status": "failed",
                "error_type": type(exc).__name__,
                "run_id": args.run_id,
            }),
            flush=True,
        )
        return 1

    print(json.dumps(summary, indent=2, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
