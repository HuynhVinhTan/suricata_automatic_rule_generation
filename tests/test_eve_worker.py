import json
import os
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from netids.eve_worker import (
    FlowModelAdapter,
    JsonlEveReader,
    StreamingInferenceWorker,
)


def flow_event(flow_id=1, *, timestamp="2026-11-13T10:00:00+00:00"):
    return {
        "timestamp": timestamp,
        "event_type": "flow",
        "flow_id": flow_id,
        "src_ip": "192.0.2.10",
        "dest_ip": "198.51.100.20",
        "proto": "TCP",
        "flow": {
            "pkts_toserver": 4,
            "pkts_toclient": 3,
            "bytes_toserver": 400,
            "bytes_toclient": 300,
            "start": timestamp,
            "end": "2026-11-13T10:00:01+00:00",
        },
    }


def real_model_adapter():
    model = RandomForestClassifier(n_estimators=4, random_state=7)
    X = np.array([[1, 0, 0, 0], [1, 1, 1, 1], [0, 2, 2, 2], [0, 3, 3, 3]])
    model.fit(pd.DataFrame(X, columns=[
        "protocol_tcp", "duration_log", "packets_log", "bytes_log"
    ]), [0, 0, 1, 1])
    metadata = {
        "artifact_version": 1,
        "schema_version": "flow_features_v0.1",
        "feature_columns": [
            "protocol_tcp", "duration_log", "packets_log", "bytes_log"
        ],
        "model_sha256": "test-model-sha",
        "model_name": "random_forest",
    }
    return FlowModelAdapter(model, metadata)


def test_reader_keeps_partial_lines_and_deduplicates(tmp_path):
    path = tmp_path / "eve.json"
    event = flow_event()
    encoded = json.dumps(event)
    path.write_text(encoded[:40], encoding="utf-8")
    reader = JsonlEveReader(path)

    assert reader.read_available() == []
    with path.open("a", encoding="utf-8") as stream:
        stream.write(encoded[40:] + "\n" + encoded + "\n")

    records = reader.read_available()
    assert len(records) == 1
    assert records[0]["flow_id"] == 1


def test_reader_recovers_from_rotation(tmp_path):
    path = tmp_path / "eve.json"
    path.write_text(json.dumps(flow_event(1)) + "\n", encoding="utf-8")
    reader = JsonlEveReader(path)
    assert [item["flow_id"] for item in reader.read_available()] == [1]

    rotated = tmp_path / "eve.json.1"
    path.replace(rotated)
    path.write_text(json.dumps(flow_event(2)) + "\n", encoding="utf-8")
    assert [item["flow_id"] for item in reader.read_available()] == [2]


def test_reader_rejects_malformed_json_without_stopping(tmp_path):
    path = tmp_path / "eve.json"
    path.write_text("not-json\n" + json.dumps(flow_event(3)) + "\n", encoding="utf-8")
    reader = JsonlEveReader(path)

    records = reader.read_available()
    assert [item["flow_id"] for item in records] == [3]
    assert reader.stats.malformed_lines == 1


def test_worker_runs_real_flow_model_and_emits_fail_closed_hybrid(tmp_path):
    path = tmp_path / "eve.json"
    output = tmp_path / "anomalies.jsonl"
    path.write_text(json.dumps(flow_event()) + "\n", encoding="utf-8")
    worker = StreamingInferenceWorker(
        reader=JsonlEveReader(path),
        model=real_model_adapter(),
        output_path=output,
        run_id="stream-test",
        window_seconds=10,
    )

    result = worker.run_once()
    assert result.processed_events == 1
    record = json.loads(output.read_text(encoding="utf-8").splitlines()[0])
    assert record["feature_schema_version"] == "flow_features_v0.1"
    assert record["provenance"]["run_id"] == "stream-test"
    assert record["hybrid"]["classification"] == "unavailable_missing_packet_telemetry"
    assert record["review_state"] == "REVIEW_ONLY"


def test_worker_uses_bounded_queue_and_counts_backpressure(tmp_path):
    path = tmp_path / "eve.json"
    path.write_text(
        "".join(json.dumps(flow_event(i)) + "\n" for i in range(3)),
        encoding="utf-8",
    )
    worker = StreamingInferenceWorker(
        reader=JsonlEveReader(path),
        model=real_model_adapter(),
        output_path=tmp_path / "out.jsonl",
        run_id="bounded",
        max_queue_size=1,
    )
    worker._queue.put_nowait(flow_event(99))

    result = worker.run_once()
    assert result.dropped_events >= 1
    assert worker.queue_size <= 1


def test_worker_connects_authorized_packet_telemetry_to_hybrid_decision(tmp_path):
    path = tmp_path / "eve.json"
    event = flow_event()
    event["netids"] = {
        "hybrid": {
            "rst_evidence": {
                "capture_integrity": {"capture_complete": True},
                "max_rst_count_per_window": 24,
            },
            "port_evidence": {"max_window_distinct_ports": 24},
            "handshake_evidence": {
                "initial_syn_packets": 24,
                "flows_with_confirmed_handshake": 0,
                "flows_with_bidirectional_payload": 0,
            },
            "thresholds": {
                "min_unique_destination_ports": 13,
                "min_rst_count_per_window": 1,
                "max_handshake_failure_count": 0,
            },
        }
    }
    path.write_text(json.dumps(event) + "\n", encoding="utf-8")
    output = tmp_path / "out.jsonl"
    worker = StreamingInferenceWorker(
        reader=JsonlEveReader(path),
        model=real_model_adapter(),
        output_path=output,
        run_id="hybrid-telemetry",
    )

    worker.run_once()
    record = json.loads(output.read_text(encoding="utf-8").splitlines()[0])
    assert record["hybrid"]["classification"] != "unavailable_missing_packet_telemetry"


def test_worker_shutdown_is_graceful(tmp_path):
    path = tmp_path / "eve.json"
    path.write_text("", encoding="utf-8")
    worker = StreamingInferenceWorker(
        reader=JsonlEveReader(path),
        model=real_model_adapter(),
        output_path=tmp_path / "out.jsonl",
        run_id="shutdown",
    )
    worker.request_shutdown()
    assert worker.run_forever(poll_interval=0) == "shutdown"
