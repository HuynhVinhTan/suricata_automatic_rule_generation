"""Bounded, fail-closed streaming inference for Suricata EVE flow JSONL.

The worker deliberately uses the EVE-compatible ``flow_features_v0.1``
contract.  It never maps an EVE flow into the packet-derived SYN contract.
Packet-level Hybrid evidence may be supplied by an authorized telemetry
adapter under ``event['netids']['hybrid']``; otherwise review remains blocked.
"""

from __future__ import annotations

import hashlib
import json
import queue
import threading
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

from netids.adapters.suricata import suricata_eve_to_features
from netids.features.schema import SCHEMA_VERSION, validate_feature_matrix
from netids.hybrid_review import evaluate_hybrid


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _event_time(event: dict) -> datetime:
    flow = event.get("flow")
    value = flow.get("end") if isinstance(flow, dict) else event.get("timestamp")
    if value is None:
        value = event.get("timestamp")
    if not isinstance(value, str):
        raise ValueError("EVE timestamp is required")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Invalid EVE timestamp") from exc
    if parsed.utcoffset() is None:
        raise ValueError("EVE timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


@dataclass
class ReaderStats:
    malformed_lines: int = 0
    duplicate_events: int = 0
    rotated_files: int = 0
    incomplete_lines: int = 0


class JsonlEveReader:
    """Incrementally read complete JSONL records and survive rotation."""

    def __init__(self, path: str | Path, *, max_line_bytes: int = 1_000_000, dedupe_limit: int = 10_000):
        if max_line_bytes < 128 or dedupe_limit < 1:
            raise ValueError("Reader bounds must be positive")
        self.path = Path(path)
        self.max_line_bytes = max_line_bytes
        self.dedupe_limit = dedupe_limit
        self.offset = 0
        self._identity: tuple[int, int] | None = None
        self._partial = b""
        self._seen_order: deque[str] = deque(maxlen=dedupe_limit)
        self._seen: set[str] = set()
        self.stats = ReaderStats()

    def _reset_for_rotation(self, identity: tuple[int, int]) -> None:
        self.offset = 0
        self._partial = b""
        self._identity = identity
        self.stats.rotated_files += 1

    def _event_identity(self, event: dict) -> str:
        explicit = event.get("event_id")
        if explicit is not None:
            return str(explicit)
        return _canonical_sha256({
            "event_type": event.get("event_type"),
            "flow_id": event.get("flow_id"),
            "timestamp": event.get("timestamp"),
            "src_ip": event.get("src_ip"),
            "dest_ip": event.get("dest_ip"),
            "proto": event.get("proto"),
            "flow": event.get("flow"),
        })

    def _remember(self, identity: str) -> bool:
        if identity in self._seen:
            self.stats.duplicate_events += 1
            return False
        if len(self._seen_order) == self.dedupe_limit:
            self._seen.discard(self._seen_order[0])
        self._seen_order.append(identity)
        self._seen.add(identity)
        return True

    def read_available(self) -> list[dict]:
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            return []

        identity = (int(stat.st_dev), int(stat.st_ino))
        if self._identity is None:
            self._identity = identity
        elif identity != self._identity or stat.st_size < self.offset:
            self._reset_for_rotation(identity)

        with self.path.open("rb") as stream:
            stream.seek(self.offset)
            chunk = stream.read()
            self.offset = stream.tell()

        if not chunk:
            return []
        data = self._partial + chunk
        lines = data.split(b"\n")
        self._partial = lines.pop()
        if self._partial:
            self.stats.incomplete_lines += 1
            if len(self._partial) > self.max_line_bytes:
                self._partial = b""
                self.stats.malformed_lines += 1

        records = []
        for raw in lines:
            if not raw.strip():
                continue
            if len(raw) > self.max_line_bytes:
                self.stats.malformed_lines += 1
                continue
            try:
                event = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self.stats.malformed_lines += 1
                continue
            if not isinstance(event, dict) or not self._remember(self._event_identity(event)):
                if not isinstance(event, dict):
                    self.stats.malformed_lines += 1
                continue
            records.append(event)
        return records


@dataclass
class WorkerResult:
    processed_events: int = 0
    rejected_events: int = 0
    dropped_events: int = 0


class FlowModelAdapter:
    """Inference adapter enforcing the exact EVE flow feature contract."""

    def __init__(self, model, metadata: dict):
        if metadata.get("schema_version") != SCHEMA_VERSION:
            raise ValueError("Model schema is not EVE-compatible")
        if metadata.get("feature_columns") != [
            "protocol_tcp", "duration_log", "packets_log", "bytes_log"
        ]:
            raise ValueError("Model feature order mismatch")
        if not isinstance(metadata.get("model_sha256"), str) or not metadata["model_sha256"]:
            raise ValueError("Model provenance hash is required")
        classes = list(getattr(model, "classes_", []))
        if classes != [0, 1]:
            raise ValueError("Model must expose binary classes [0, 1]")
        self.model = model
        self.metadata = dict(metadata)

    def infer(self, event: dict) -> dict:
        features = suricata_eve_to_features(event)
        matrix = validate_feature_matrix(pd.DataFrame([features]))
        scores = self.model.predict_proba(matrix)
        if scores.shape != (1, 2):
            raise ValueError("Model returned an invalid probability matrix")
        score = float(scores[0, 1])
        if not 0 <= score <= 1:
            raise ValueError("Model returned an invalid probability")
        return {"features": features, "score": score, "anomalous": score >= 0.5}


class _WindowAggregator:
    def __init__(self, seconds: int):
        if seconds < 1:
            raise ValueError("Window seconds must be positive")
        self.seconds = seconds
        self._windows: dict[tuple[str, int], dict[str, Any]] = {}

    def add(self, event: dict, score: float, anomalous: bool) -> dict:
        timestamp = _event_time(event)
        epoch = int(timestamp.timestamp())
        start = epoch - (epoch % self.seconds)
        key = (
            str(event.get("src_ip", "")),
            str(event.get("dest_ip", "")),
            str(event.get("proto", "")).upper(),
            start,
        )
        window = self._windows.setdefault(key, {"events": 0, "anomalies": 0, "max_score": 0.0})
        window["events"] += 1
        window["anomalies"] += int(anomalous)
        window["max_score"] = max(window["max_score"], score)
        return {
            "source_ip": key[0],
            "destination_ip": key[1],
            "protocol": key[2],
            "start_unix": key[3],
            "seconds": self.seconds,
            **window,
        }


class StreamingInferenceWorker:
    """Read, infer and emit review-only anomaly evidence with bounded memory."""

    def __init__(self, *, reader: JsonlEveReader, model: FlowModelAdapter, output_path: str | Path,
                 run_id: str, window_seconds: int = 10, max_queue_size: int = 1024):
        if not run_id.strip() or max_queue_size < 1:
            raise ValueError("run_id and queue bound are required")
        self.reader = reader
        self.model = model
        self.output_path = Path(output_path)
        self.run_id = run_id
        self._queue: queue.Queue[dict] = queue.Queue(maxsize=max_queue_size)
        self._windows = _WindowAggregator(window_seconds)
        self._stop = threading.Event()
        self._output_lock = threading.Lock()
        self._rejected = 0

    @property
    def queue_size(self) -> int:
        return self._queue.qsize()

    def request_shutdown(self) -> None:
        self._stop.set()

    def _hybrid(self, event: dict, anomalous: bool) -> dict:
        telemetry = event.get("netids", {}).get("hybrid") if isinstance(event.get("netids"), dict) else None
        if not isinstance(telemetry, dict):
            return {
                "schema_version": "hybrid_review_v1",
                "classification": "unavailable_missing_packet_telemetry",
                "requires_manual_review": True,
                "approved": False,
                "deployable": False,
            }
        required = {"rst_evidence", "port_evidence", "handshake_evidence", "thresholds"}
        if not required.issubset(telemetry):
            raise ValueError("Incomplete Hybrid telemetry")
        return evaluate_hybrid(
            ml_consensus=anomalous,
            rst_evidence=telemetry["rst_evidence"],
            port_evidence=telemetry["port_evidence"],
            handshake_evidence=telemetry["handshake_evidence"],
            thresholds=telemetry["thresholds"],
        )

    def _emit(self, event: dict) -> None:
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        with self._output_lock, self.output_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event, sort_keys=True, ensure_ascii=False) + "\n")

    def _process(self, event: dict) -> None:
        inference = self.model.infer(event)
        hybrid = self._hybrid(event, inference["anomalous"])
        window = self._windows.add(event, inference["score"], inference["anomalous"])
        event_sha = _canonical_sha256(event)
        record = {
            "schema_version": "netids_stream_anomaly_v1",
            "detection_id": hashlib.sha256(f"{self.run_id}:{event_sha}".encode()).hexdigest(),
            "run_id": self.run_id,
            "event_time": _event_time(event).isoformat(),
            "feature_schema_version": SCHEMA_VERSION,
            "features": inference["features"],
            "ml": {
                "score": inference["score"],
                "anomalous": inference["anomalous"],
            },
            "hybrid": hybrid,
            "decision": "review_required" if inference["anomalous"] else "normal_or_insufficient_evidence",
            "review_state": "REVIEW_ONLY",
            "window": window,
            "provenance": {
                "run_id": self.run_id,
                "event_sha256": event_sha,
                "model_sha256": self.model.metadata["model_sha256"],
                "model_name": self.model.metadata.get("model_name"),
                "source": "suricata_eve_jsonl",
            },
        }
        self._emit(record)

    def run_once(self) -> WorkerResult:
        result = WorkerResult()
        for event in self.reader.read_available():
            try:
                self._queue.put_nowait(event)
            except queue.Full:
                result.dropped_events += 1
        while True:
            try:
                event = self._queue.get_nowait()
            except queue.Empty:
                break
            try:
                self._process(event)
                result.processed_events += 1
            except (KeyError, TypeError, ValueError, OverflowError):
                self._rejected += 1
                result.rejected_events += 1
            finally:
                self._queue.task_done()
        return result

    def run_forever(self, *, poll_interval: float = 0.25) -> str:
        if poll_interval < 0:
            raise ValueError("poll_interval cannot be negative")
        while not self._stop.is_set():
            self.run_once()
            if poll_interval:
                self._stop.wait(poll_interval)
        return "shutdown"
