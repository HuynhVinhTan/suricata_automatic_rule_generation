import json

import pytest

from netids.latency import LatencyTrace, validate_latency_trace
from netids.latency_aggregation import LatencyEvidenceError, aggregate_latency


def _trace(run_id="run-1"):
    trace = LatencyTrace(
        run_id=run_id,
        host="synthetic-host",
        clock_sync={"status": "same_host_monotonic", "offset_ms": 0.0},
    )
    with trace.stage("capture", component="capture"):
        pass
    with trace.stage("outer", component="runtime"):
        with trace.stage("inner", component="runtime"):
            pass
    trace.record("failed_operation", status="error", elapsed_ms=4.0, component="runtime")
    trace.record("not_available", status="not_measured", component="human")
    return trace.as_dict()


def test_latency_trace_validation_accepts_nested_and_failed_stages():
    trace = _trace()
    validate_latency_trace(trace, expected_run_id="run-1")
    assert {stage["name"] for stage in trace["stages"]} >= {"outer", "inner"}
    assert any(stage["status"] == "error" for stage in trace["stages"])


def test_latency_trace_validation_rejects_invalid_clock_data_and_identity():
    trace = _trace()
    broken_clock = json.loads(json.dumps(trace))
    broken_clock["clock"]["synchronization"]["offset_ms"] = "unknown"
    with pytest.raises(ValueError, match="clock"):
        validate_latency_trace(broken_clock, expected_run_id="run-1")

    with pytest.raises(ValueError, match="run_id"):
        validate_latency_trace(trace, expected_run_id="different-run")


def test_latency_trace_allows_monotonic_stage_without_wall_timestamps():
    trace = _trace()
    for stage in trace["stages"]:
        stage.pop("started_at_utc", None)
        stage.pop("ended_at_utc", None)
    validate_latency_trace(trace, expected_run_id="run-1")


def test_aggregate_latency_preserves_measured_failed_and_not_measured(tmp_path):
    evidence = tmp_path / "runtime.json"
    evidence.write_text(
        json.dumps({
            "schema_version": "synthetic_latency_evidence_v1",
            "run_id": "run-1",
            "latency_trace": _trace(),
        }),
        encoding="utf-8",
    )
    output = tmp_path / "aggregated"
    result = aggregate_latency([evidence], output)
    assert result["accepted_runs"] == 1
    assert (output / "latency_per_run.csv").is_file()
    assert (output / "latency_stage_summary.csv").is_file()
    assert (output / "latency_coverage.json").is_file()
    assert (output / "latency_report.md").is_file()
    assert (output / "evidence_manifest.json").is_file()
    summary = (output / "latency_stage_summary.csv").read_text(encoding="utf-8")
    assert "failed_operation" in summary
    assert "not_available" in summary
    assert ",1," in summary


def test_aggregate_latency_rejects_trace_evidence_binding_mismatch(tmp_path):
    evidence = tmp_path / "mismatch.json"
    evidence.write_text(
        json.dumps({
            "schema_version": "synthetic_latency_evidence_v1",
            "run_id": "evidence-run",
            "latency_trace": _trace("trace-run"),
        }),
        encoding="utf-8",
    )
    with pytest.raises(LatencyEvidenceError, match="run_id"):
        aggregate_latency([evidence], tmp_path / "aggregated")
