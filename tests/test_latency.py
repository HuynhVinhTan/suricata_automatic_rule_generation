import json

import pytest

from netids.latency import LatencyTrace


def test_latency_trace_records_monotonic_elapsed_and_utc(tmp_path):
    trace = LatencyTrace(run_id="latency-test-1")
    with trace.stage("feature_extraction"):
        pass
    result = trace.as_dict()
    assert result["schema_version"] == "latency_trace_v1"
    assert result["stages"][0]["elapsed_ms"] >= 0
    assert result["stages"][0]["started_at_utc"].endswith("+00:00")
    json.dumps(result)


def test_latency_trace_rejects_duplicate_active_stage_and_open_serialization():
    trace = LatencyTrace(run_id="latency-test-2")
    with pytest.raises(ValueError, match="already active"):
        with trace.stage("same"):
            with trace.stage("same"):
                pass
    assert trace.as_dict()["stages"][0]["status"] == "error"


def test_latency_trace_preserves_failed_stage_and_external_unmeasured_marker():
    trace = LatencyTrace(run_id="latency-test-3")
    with pytest.raises(RuntimeError):
        with trace.stage("activation"):
            raise RuntimeError("blocked")
    trace.record("rollback", status="not_measured")
    assert trace.as_dict()["stages"][0]["error_type"] == "RuntimeError"
    assert trace.as_dict()["stages"][1]["status"] == "not_measured"
    assert "elapsed_ms" not in trace.as_dict()["stages"][1]


def test_not_measured_cannot_be_zero_milliseconds():
    trace = LatencyTrace(run_id="latency-test-4")
    with pytest.raises(ValueError, match="cannot contain"):
        trace.record("activation", 0, status="not_measured")
