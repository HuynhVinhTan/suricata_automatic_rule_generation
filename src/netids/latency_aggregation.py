"""Strict offline aggregation for verified latency evidence.

This module never derives durations by subtracting monotonic clocks from
different machines.  Cross-host evidence must provide an externally verified
elapsed duration or an explicit clock-synchronization record.
"""

from __future__ import annotations

import csv
import hashlib
import json
import math
from pathlib import Path

from netids.latency import validate_latency_trace


class LatencyEvidenceError(ValueError):
    """Evidence is incomplete, inconsistent, or not bound to its trace."""


# The repository establishes only that T8-T11 are activation-dependent.  The
# exact T0-T11 labels remain a proposed mapping until the owner supplies the
# historical G6 measurement contract.
T0_T11_CATALOG = (
    ("T0", "capture", "Bắt đầu capture", "VM2", "UTC wall-clock", "capture"),
    ("T1", "capture_sealing", "Sealing capture", "VM2", "monotonic/UTC", "capture"),
    ("T2", "handoff_transport", "Transport handoff", "VM1→VM3", "UTC + clock offset", "transport"),
    ("T3", "handoff_receipt", "Receipt handoff", "VM3", "UTC wall-clock", "transport"),
    ("T4", "worker_queue", "Worker queue wait", "VM3", "monotonic", "worker"),
    ("T5", "worker_processing", "Worker processing", "VM3", "monotonic", "worker"),
    ("T6", "feature_extraction", "Feature extraction", "VM3", "monotonic", "ai"),
    ("T7", "model_inference", "ML/DL inference", "VM3", "monotonic", "ai"),
    ("T8", "hybrid_evaluation", "Hybrid evaluation/candidate validation", "VM3", "monotonic", "hybrid"),
    ("T9", "replay_attestation", "Replay attestation and owner wait", "Owner/VM1", "UTC + monotonic", "human"),
    ("T10", "isolated_runtime_activation", "Isolated activation and probes", "VM1", "monotonic", "runtime"),
    ("T11", "mandatory_rollback", "Rollback and post-rollback verification", "VM1", "monotonic", "runtime"),
)

_CATALOG_BY_NAME = {row[1]: row for row in T0_T11_CATALOG}
_COMPONENT_BY_NAME = {row[1]: row[5] for row in T0_T11_CATALOG}
_COMPONENT_BY_NAME.update({
    "candidate_generation": "hybrid",
    "candidate_validation": "hybrid",
    "owner_approval_wait": "human",
    "isolated_runtime_activation": "runtime",
    "probe_verification_active": "runtime",
    "probe_verification_rollback": "runtime",
    "post_rollback_verification": "runtime",
})


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return round(ordered[lower], 3)
    weight = position - lower
    return round(ordered[lower] + (ordered[upper] - ordered[lower]) * weight, 3)


def _mean(values: list[float]) -> float | None:
    return round(sum(values) / len(values), 3) if values else None


def _stddev(values: list[float]) -> float | None:
    if len(values) < 2:
        return None
    mean = sum(values) / len(values)
    return round((sum((value - mean) ** 2 for value in values) / (len(values) - 1)) ** 0.5, 3)


def _value_or_empty(value: float | None) -> float | str:
    return "" if value is None else value


def _component(name: str, explicit: object) -> str:
    if isinstance(explicit, str) and explicit.strip():
        return explicit
    return _COMPONENT_BY_NAME.get(name, "unclassified")


def load_latency_evidence(path: str | Path) -> dict:
    """Load one evidence envelope and require exact trace/evidence identity."""
    evidence_path = Path(path)
    try:
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LatencyEvidenceError(f"cannot read latency evidence: {evidence_path}") from exc
    if not isinstance(evidence, dict):
        raise LatencyEvidenceError("latency evidence must be an object")
    evidence_run_id = evidence.get("run_id")
    if not isinstance(evidence_run_id, str) or not evidence_run_id.strip():
        raise LatencyEvidenceError("latency evidence run_id is missing")
    trace = evidence.get("latency_trace") or evidence.get("latency")
    if not isinstance(trace, dict):
        raise LatencyEvidenceError("latency evidence has no latency_trace")
    try:
        validate_latency_trace(trace, expected_run_id=evidence_run_id)
    except ValueError as exc:
        raise LatencyEvidenceError(str(exc)) from exc
    return {
        "path": evidence_path,
        "evidence": evidence,
        "trace": trace,
        "run_id": evidence_run_id,
    }


def _row(run: dict, stage: dict, *, validity: str, elapsed_ms: float | None) -> dict:
    name = stage["name"]
    catalog = _CATALOG_BY_NAME.get(name)
    return {
        "run_id": run["run_id"],
        "evidence_file": str(run["path"]),
        "stage": name,
        "t_stage": catalog[0] if catalog else "UNMAPPED",
        "component": _component(name, stage.get("component")),
        "host": (run["trace"].get("clock") or {}).get("host", ""),
        "clock_type": stage.get("clock_type", "unknown"),
        "status": stage.get("status", "unknown"),
        "validity": validity,
        "elapsed_ms": "" if elapsed_ms is None else elapsed_ms,
        "label": stage.get("label", ""),
    }


def _write_csv(path: Path, rows: list[dict], fields: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def aggregate_latency(evidence_paths: list[str | Path], output_dir: str | Path) -> dict:
    """Aggregate only valid evidence and preserve failed/missing statuses."""
    if not evidence_paths:
        raise LatencyEvidenceError("at least one verified evidence file is required")
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    runs = [load_latency_evidence(path) for path in evidence_paths]
    per_run: list[dict] = []
    coverage: dict[str, dict] = {}
    for run in runs:
        observed = set()
        for stage in run["trace"]["stages"]:
            name = stage["name"]
            observed.add(name)
            elapsed = stage.get("elapsed_ms")
            if stage.get("status") == "not_measured":
                validity = "not_measured"
                elapsed = None
            elif stage.get("status") in {"error", "failed"}:
                validity = "failed"
            elif isinstance(elapsed, (int, float)):
                validity = "measured"
            else:
                validity = "missing"
            per_run.append(_row(run, stage, validity=validity, elapsed_ms=elapsed))
        for _code, name, _definition, _host, _clock, _component_name in T0_T11_CATALOG:
            if name not in observed:
                per_run.append(_row(
                    run,
                    {"name": name, "status": "missing", "component": _component_name, "clock_type": "unknown"},
                    validity="missing",
                    elapsed_ms=None,
                ))
        coverage[run["run_id"]] = {
            "evidence_file": str(run["path"]),
            "observed_stage_count": len(observed),
            "catalog_stage_count": len(T0_T11_CATALOG),
            "observed_stages": sorted(observed),
            "missing_catalog_stages": [name for _code, name, *_ in T0_T11_CATALOG if name not in observed],
        }

    summary: list[dict] = []
    for stage_name in sorted({row["stage"] for row in per_run}):
        rows = [row for row in per_run if row["stage"] == stage_name]
        values = [float(row["elapsed_ms"]) for row in rows if row["validity"] == "measured"]
        summary.append({
            "stage": stage_name,
            "t_stage": rows[0]["t_stage"],
            "component": rows[0]["component"],
            "valid_observations": len(values),
            "minimum_ms": round(min(values), 3) if values else "",
            "mean_ms": _value_or_empty(_mean(values)),
            "median_ms": _value_or_empty(_percentile(values, 0.5)),
            "p95_ms": _value_or_empty(_percentile(values, 0.95)),
            "maximum_ms": round(max(values), 3) if values else "",
            "stddev_ms": _value_or_empty(_stddev(values)),
            "failed_observations": sum(row["validity"] == "failed" for row in rows),
            "not_measured_observations": sum(row["validity"] == "not_measured" for row in rows),
            "missing_observations": sum(row["validity"] == "missing" for row in rows),
        })

    per_run_fields = ["run_id", "evidence_file", "stage", "t_stage", "component", "host", "clock_type", "status", "validity", "elapsed_ms", "label"]
    summary_fields = ["stage", "t_stage", "component", "valid_observations", "minimum_ms", "mean_ms", "median_ms", "p95_ms", "maximum_ms", "stddev_ms", "failed_observations", "not_measured_observations", "missing_observations"]
    _write_csv(output / "latency_per_run.csv", per_run, per_run_fields)
    _write_csv(output / "latency_stage_summary.csv", summary, summary_fields)

    coverage_doc = {
        "schema_version": "latency_coverage_v1",
        "t0_t11_definition_status": "proposed_mapping_only; repository lacks an authoritative exact T0-T11 contract",
        "catalog": [
            {"t_stage": code, "stage": name, "definition": definition, "host": host, "clock_type": clock, "component": component}
            for code, name, definition, host, clock, component in T0_T11_CATALOG
        ],
        "runs": coverage,
    }
    (output / "latency_coverage.json").write_text(json.dumps(coverage_doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    report_lines = [
        "# Latency aggregation report",
        "",
        "This report contains only trace durations supplied by the evidence files.",
        "Missing, failed and NOT_MEASURED observations are not converted to zero.",
        "The T0–T11 mapping is proposed because the repository has no authoritative exact definition.",
        "",
        f"Accepted runs: {len(runs)}",
        f"Measured stage observations: {sum(row['validity'] == 'measured' for row in per_run)}",
        f"Failed observations: {sum(row['validity'] == 'failed' for row in per_run)}",
        f"NOT_MEASURED observations: {sum(row['validity'] == 'not_measured' for row in per_run)}",
        f"Missing observations: {sum(row['validity'] == 'missing' for row in per_run)}",
        "",
        "A single run cannot establish population-level percentiles.",
    ]
    (output / "latency_report.md").write_text("\n".join(report_lines) + "\n", encoding="utf-8")

    manifest = {
        "schema_version": "latency_evidence_manifest_v1",
        "files": [
            {"path": str(run["path"]), "sha256": _sha256(run["path"]), "run_id": run["run_id"], "accepted": True}
            for run in runs
        ],
        "outputs": {
            name: _sha256(output / name)
            for name in ("latency_per_run.csv", "latency_stage_summary.csv", "latency_coverage.json", "latency_report.md")
        },
    }
    (output / "evidence_manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return {"accepted_runs": len(runs), "measured_observations": sum(row["validity"] == "measured" for row in per_run), "output_dir": str(output)}
