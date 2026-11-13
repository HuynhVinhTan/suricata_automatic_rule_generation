import json
from pathlib import Path

import pandas as pd
import pytest

from netids.models.ml import make_ml_pipeline
from netids.showcase_demo import ShowcaseDemoFlowModelAdapter, load_showcase_demo_artifact
from scripts.build_showcase_dataset import correlate_sessions
from scripts.train_showcase_model import session_metrics, validate_split_disjointness


def _model_and_metadata(tmp_path):
    model = make_ml_pipeline("logistic_regression")
    X = pd.DataFrame([
        {"protocol_tcp": 1, "duration_log": 0.1, "packets_log": 1.0, "bytes_log": 2.0},
        {"protocol_tcp": 1, "duration_log": 2.0, "packets_log": 3.0, "bytes_log": 6.0},
    ])
    model.fit(X, [0, 1])
    import joblib
    path = tmp_path / "pipeline.joblib"
    joblib.dump(model, path)
    import hashlib
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    metadata = {
        "artifact_version": 1, "status": "demo_only", "demo_only": True, "profile": "showcase_demo",
        "model_name": "logistic_regression", "schema_version": "flow_features_v0.1",
        "feature_columns": ["protocol_tcp", "duration_log", "packets_log", "bytes_log"],
        "model_sha256": digest, "decision_threshold": 0.5,
        "threshold_provenance": {"decision_threshold": 0.5, "status": "demo_only", "calibration_method": "max_f1_on_calibration", "calibration_version": "showcase-calibration-v1", "calibration_manifest_sha256": "a" * 64},
        "source_dataset": {"development_manifest_sha256": "b" * 64, "calibration_manifest_sha256": "c" * 64, "holdout_manifest_sha256": "d" * 64, "split_disjointness": "verified", "split_plan": {}},
        "calibration": {"records": 2, "method": "fixed_test"},
    }
    (tmp_path / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
    return tmp_path, model, metadata


def test_showcase_adapter_is_explicit_and_review_only(tmp_path):
    folder, model, metadata = _model_and_metadata(tmp_path)
    restored, readback = load_showcase_demo_artifact(folder)
    result = ShowcaseDemoFlowModelAdapter(restored, readback).infer({
        "event_type": "flow", "timestamp": "2026-01-01T00:00:00Z", "proto": "TCP",
        "flow": {"start": "2026-01-01T00:00:00Z", "end": "2026-01-01T00:00:01Z",
                 "pkts_toserver": 1, "pkts_toclient": 1, "bytes_toserver": 10, "bytes_toclient": 10},
    })
    assert result["profile"] == "showcase_demo"
    assert result["demo_only"] is True
    assert result["approved"] is False and result["deployable"] is False and result["deployed"] is False
    assert result["review_state"] == "REVIEW_ONLY"


def test_showcase_loader_rejects_non_demo_artifact(tmp_path):
    folder, _, _ = _model_and_metadata(tmp_path)
    metadata_path = folder / "metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["status"] = "verified"
    metadata["demo_only"] = False
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    with pytest.raises(ValueError, match="demo_only"):
        load_showcase_demo_artifact(folder)


def test_showcase_loader_rejects_threshold_provenance_mismatch(tmp_path):
    folder, _, _ = _model_and_metadata(tmp_path)
    metadata_path = folder / "metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["threshold_provenance"]["decision_threshold"] = 0.4
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    with pytest.raises(ValueError, match="threshold"):
        load_showcase_demo_artifact(folder)


def test_correlator_requires_exact_tuple_and_bounded_time(tmp_path):
    manifest = {
        "run_id": "dev-a", "scenario": "ATTACK", "attempts": [{
            "attempt_id": "dev-a-001", "timestamp_utc": "2026-01-01T00:00:00Z",
            "attempt_end_utc": "2026-01-01T00:00:02Z", "source_ip": "192.168.10.20",
            "source_port": 40000, "target_ip": "192.168.10.10", "destination_port": 18100,
            "protocol": "TCP", "result": "rst_refused",
        }],
    }
    eve = {"event_type": "flow", "timestamp": "2026-01-01T00:00:01Z", "src_ip": "192.168.10.20",
           "src_port": 40000, "dest_ip": "192.168.10.10", "dest_port": 18100, "proto": "TCP",
           "flow": {"start": "2026-01-01T00:00:00Z", "end": "2026-01-01T00:00:01Z",
                    "pkts_toserver": 1, "pkts_toclient": 0, "bytes_toserver": 0, "bytes_toclient": 0}}
    assert len(correlate_sessions([manifest], [eve])) == 1
    eve["src_port"] = 40001
    assert correlate_sessions([manifest], [eve]) == []


def test_normal_rst_control_is_not_a_binary_normal_label():
    manifest = {"run_id": "normal-1", "scenario": "NORMAL", "attempts": [{
        "attempt_id": "normal-1-001", "timestamp_utc": "2026-01-01T00:00:00Z",
        "attempt_end_utc": "2026-01-01T00:00:02Z", "source_ip": "192.168.10.20",
        "source_port": 40000, "target_ip": "192.168.10.10", "destination_port": 18100,
        "protocol": "TCP", "result": "rst_refused", "http_status": None,
    }]}
    eve = {"event_type": "flow", "flow_id": 7, "timestamp": "2026-01-01T00:00:01Z",
           "src_ip": "192.168.10.20", "src_port": 40000, "dest_ip": "192.168.10.10",
           "dest_port": 18100, "proto": "TCP", "flow": {"start": "2026-01-01T00:00:00Z",
           "end": "2026-01-01T00:00:01Z", "pkts_toserver": 1, "pkts_toclient": 1,
           "bytes_toserver": 10, "bytes_toclient": 10}}
    row = correlate_sessions([manifest], [eve])[0]
    assert row["category"] == "negative_control"
    assert row["binary_eligible"] is False
    assert row["label"] is None


def test_split_disjointness_rejects_session_attempt_and_event_overlap():
    base = {"run_id": "run-a", "attempt_id": "attempt-a", "event_sha256": "a" * 64, "label": 0}
    with pytest.raises(ValueError, match="session"):
        validate_split_disjointness({"development": [base], "calibration": [{**base, "attempt_id": "attempt-b", "event_sha256": "b" * 64}]})
    with pytest.raises(ValueError, match="attempt"):
        validate_split_disjointness({"development": [base], "calibration": [{**base, "run_id": "run-b", "event_sha256": "b" * 64}]})
    with pytest.raises(ValueError, match="event"):
        validate_split_disjointness({"development": [base], "calibration": [{**base, "run_id": "run-b", "attempt_id": "attempt-b"}]})


def test_session_metrics_keep_control_records_out_of_binary_rate():
    rows = [{"run_id": "attack-1", "scenario": "ATTACK", "binary_eligible": True},
            {"run_id": "normal-1", "scenario": "NORMAL", "binary_eligible": True},
            {"run_id": "normal-1", "scenario": "NORMAL", "binary_eligible": False}]
    assert session_metrics(rows, [0.9, 0.1, 0.9], 0.5) == {
        "attack_sessions": 1, "attack_detected": 1, "attack_session_detection_rate": 1.0,
        "normal_sessions": 1, "normal_false_alerts": 0, "normal_session_false_alert_rate": 0.0,
    }
