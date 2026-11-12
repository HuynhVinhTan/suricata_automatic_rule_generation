import base64
import json
import os
import threading
import time
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
from sklearn.ensemble import RandomForestClassifier
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from netids.eve_worker import (
    FlowModelAdapter,
    JsonlEveReader,
    StreamingInferenceWorker,
)
from netids import hybrid_provenance


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
        "model_sha256": "a" * 64,
        "model_name": "random_forest",
        "status": "test_only",
    }
    return FlowModelAdapter(model, metadata, allow_test_model=True)


def signed_hybrid(event, run_id, monkeypatch):
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    fingerprint = hybrid_provenance.public_key_sha256(public)
    monkeypatch.setattr(hybrid_provenance, "PINNED_HYBRID_PRODUCER_PUBLIC_KEY_PEM", public)
    monkeypatch.setattr(hybrid_provenance, "PINNED_HYBRID_PRODUCER_SHA256", fingerprint)
    payload = {
        "rst_evidence": {"capture_integrity": {"capture_complete": True}, "max_rst_count_per_window": 24},
        "port_evidence": {"max_window_distinct_ports": 24},
        "handshake_evidence": {"initial_syn_packets": 24, "flows_with_confirmed_handshake": 0, "flows_with_bidirectional_payload": 0},
        "thresholds": {"min_unique_destination_ports": 13, "min_rst_count_per_window": 1, "max_handshake_failure_count": 0},
    }
    envelope = {
        "schema_version": "hybrid_telemetry_v1", "producer_identity": "test-producer",
        "capture_run_id": run_id, "source_pcap_sha256": "b" * 64,
        "timestamp_provenance": {"first_timestamp": "2026-11-13T09:00:00+00:00", "last_timestamp": "2026-11-13T11:00:00+00:00"},
        "producer_key_sha256": fingerprint, "payload": payload,
    }
    envelope["signature"] = base64.b64encode(private.sign(hybrid_provenance.canonical_payload(envelope))).decode()
    event["netids"] = {"hybrid": envelope}


def test_production_model_metadata_requires_verified_provenance(tmp_path):
    model = RandomForestClassifier(n_estimators=4, random_state=7)
    X = np.array([[1, 0, 0, 0], [1, 1, 1, 1], [0, 2, 2, 2], [0, 3, 3, 3]])
    model.fit(pd.DataFrame(X, columns=["protocol_tcp", "duration_log", "packets_log", "bytes_log"]), [0, 0, 1, 1])
    metadata = {"schema_version": "flow_features_v0.1", "feature_columns": ["protocol_tcp", "duration_log", "packets_log", "bytes_log"], "model_sha256": "a" * 64}
    with pytest.raises(ValueError, match="verified production"):
        FlowModelAdapter(model, metadata)


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
    reader.acknowledge(records[0])


def test_reader_recovers_from_rotation(tmp_path):
    path = tmp_path / "eve.json"
    path.write_text(json.dumps(flow_event(1)) + "\n", encoding="utf-8")
    reader = JsonlEveReader(path)
    records = reader.read_available()
    assert [item["flow_id"] for item in records] == [1]
    reader.acknowledge(records[0])

    rotated = tmp_path / "eve.json.1"
    path.replace(rotated)
    path.write_text(json.dumps(flow_event(2)) + "\n", encoding="utf-8")
    records = reader.read_available()
    assert [item["flow_id"] for item in records] == [2]


def test_reader_rejects_malformed_json_without_stopping(tmp_path):
    path = tmp_path / "eve.json"
    path.write_text("not-json\n" + json.dumps(flow_event(3)) + "\n", encoding="utf-8")
    reader = JsonlEveReader(path)

    records = reader.read_available()
    assert [item["flow_id"] for item in records] == [3]
    reader.acknowledge(records[0])
    assert reader.stats.malformed_lines == 1


def test_reader_discards_unterminated_oversized_line_without_retaining_memory(tmp_path):
    path = tmp_path / "eve.json"
    path.write_bytes(b"x" * 128)
    reader = JsonlEveReader(path, max_chunk_bytes=128, max_line_bytes=512)
    for _ in range(20):
        with path.open("ab") as stream:
            stream.write(b"x" * 128)
        reader.read_available()
        assert len(reader._partial) <= reader.max_line_bytes
    event = flow_event(77)
    with path.open("ab") as stream:
        stream.write(b"\n" + json.dumps(event).encode() + b"\n")
    output = tmp_path / "out.jsonl"
    worker = StreamingInferenceWorker(reader=reader, model=real_model_adapter(), output_path=output, run_id="oversized")
    result = worker.run_once()
    assert result.processed_events == 1
    assert json.loads(output.read_text(encoding="utf-8"))["provenance"]["event_sha256"]
    assert reader.stats.malformed_lines == 1


def test_hybrid_modified_payload_and_replay_are_unavailable(tmp_path, monkeypatch):
    event = flow_event(90)
    signed_hybrid(event, "replay-1", monkeypatch)
    event["netids"]["hybrid"]["payload"]["rst_evidence"]["max_rst_count_per_window"] = 999
    path = tmp_path / "eve.json"
    path.write_text(json.dumps(event) + "\n", encoding="utf-8")
    output = tmp_path / "out.jsonl"
    worker = StreamingInferenceWorker(reader=JsonlEveReader(path), model=real_model_adapter(), output_path=output, run_id="replay-1")
    worker.run_once()
    record = json.loads(output.read_text(encoding="utf-8"))
    assert record["hybrid"]["deployable"] is False


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


def test_worker_processes_all_valid_events_with_bounded_synchronous_backpressure(tmp_path):
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
        max_records_per_cycle=1,
    )
    results = [worker.run_once() for _ in range(3)]
    assert sum(item.processed_events for item in results) == 3
    assert sum(item.rejected_events for item in results) == 0
    assert len((tmp_path / "out.jsonl").read_text(encoding="utf-8").splitlines()) == 3


def test_reader_reads_large_file_in_bounded_chunks(tmp_path):
    path = tmp_path / "eve.json"
    path.write_text("".join(json.dumps(flow_event(i)) + "\n" for i in range(20)), encoding="utf-8")
    reader = JsonlEveReader(path, max_chunk_bytes=128)

    batches = []
    while reader.offset < path.stat().st_size or reader._partial:
        batch = reader.read_available()
        if not batch and reader.offset >= path.stat().st_size:
            break
        if batch:
            batches.append(batch)
            for event in batch:
                reader.acknowledge(event)

    assert sum(len(batch) for batch in batches) == 20
    assert len(batches) > 1


def test_partial_line_is_counted_once_across_polls(tmp_path):
    path = tmp_path / "eve.json"
    event = json.dumps(flow_event())
    path.write_text(event[:20], encoding="utf-8")
    reader = JsonlEveReader(path)
    reader.read_available()
    reader.read_available()
    assert reader.stats.incomplete_lines == 1
    with path.open("a", encoding="utf-8") as stream:
        stream.write(event[20:] + "\n")
    assert len(reader.read_available()) == 1
    assert reader.stats.incomplete_lines == 1


def test_window_state_expires_and_is_capped(tmp_path):
    path = tmp_path / "eve.json"
    events = [flow_event(i, timestamp=f"2026-11-13T10:00:{i:02d}+00:00") for i in range(6)]
    for event in events:
        event["flow"]["end"] = event["timestamp"]
    path.write_text("".join(json.dumps(event) + "\n" for event in events), encoding="utf-8")
    worker = StreamingInferenceWorker(
        reader=JsonlEveReader(path), model=real_model_adapter(), output_path=tmp_path / "out.jsonl",
        run_id="windows", window_seconds=1, window_retention_seconds=1, max_active_windows=2,
    )
    result = worker.run_once()
    assert result.processed_events == 6
    assert result.evicted_windows >= 4
    assert worker.active_window_count <= 2


def test_worker_connects_authorized_packet_telemetry_to_hybrid_decision(tmp_path, monkeypatch):
    path = tmp_path / "eve.json"
    event = flow_event()
    signed_hybrid(event, "hybrid-telemetry", monkeypatch)
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


def test_worker_rejects_unverified_hybrid_telemetry(tmp_path):
    event = flow_event()
    event["netids"] = {"hybrid": {
        "rst_evidence": {}, "port_evidence": {}, "handshake_evidence": {}, "thresholds": {},
    }}
    path = tmp_path / "eve.json"
    path.write_text(json.dumps(event) + "\n", encoding="utf-8")
    output = tmp_path / "out.jsonl"
    worker = StreamingInferenceWorker(reader=JsonlEveReader(path), model=real_model_adapter(), output_path=output, run_id="bad-hybrid")
    worker.run_once()
    record = json.loads(output.read_text(encoding="utf-8").splitlines()[0])
    assert record["hybrid"]["classification"] == "unavailable_invalid_telemetry_provenance"
    assert record["hybrid"]["deployable"] is False


def test_worker_shutdown_is_graceful(tmp_path):
    path = tmp_path / "eve.json"
    path.write_text("", encoding="utf-8")
    worker = StreamingInferenceWorker(
        reader=JsonlEveReader(path),
        model=real_model_adapter(),
        output_path=tmp_path / "out.jsonl",
        run_id="shutdown",
    )
    thread = threading.Thread(target=worker.run_forever, kwargs={"poll_interval": 0.001})
    thread.start()
    time.sleep(0.01)
    worker.request_shutdown()
    thread.join(timeout=1)
    assert not thread.is_alive()


def test_shutdown_leaves_unprocessed_records_for_restart_without_duplicates(tmp_path, monkeypatch):
    path = tmp_path / "eve.json"
    path.write_text("".join(json.dumps(flow_event(i)) + "\n" for i in range(12)), encoding="utf-8")
    output = tmp_path / "out.jsonl"
    worker = StreamingInferenceWorker(reader=JsonlEveReader(path), model=real_model_adapter(), output_path=output, run_id="restart", max_records_per_cycle=12)
    original = worker.model.infer
    def slow(event):
        time.sleep(0.01)
        return original(event)
    monkeypatch.setattr(worker.model, "infer", slow)
    thread = threading.Thread(target=worker.run_forever, kwargs={"poll_interval": 0.001})
    thread.start()
    time.sleep(0.035)
    worker.request_shutdown()
    thread.join(timeout=1)
    assert not thread.is_alive()

    restarted = StreamingInferenceWorker(reader=JsonlEveReader(path), model=real_model_adapter(), output_path=output, run_id="restart", max_records_per_cycle=12)
    while restarted.reader.offset < path.stat().st_size:
        restarted.run_once()
    records = output.read_text(encoding="utf-8").splitlines()
    assert len(records) == 12
    assert len({json.loads(line)["detection_id"] for line in records}) == 12
