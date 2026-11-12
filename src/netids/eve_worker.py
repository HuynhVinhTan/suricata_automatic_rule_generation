"""Bounded, fail-closed streaming inference for Suricata EVE flow JSONL.

The worker deliberately uses the EVE-compatible ``flow_features_v0.1``
contract.  It never maps an EVE flow into the packet-derived SYN contract.
Packet-level Hybrid evidence may be supplied by an authorized telemetry
adapter under ``event['netids']['hybrid']``; otherwise review remains blocked.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import math
import os
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

from netids.adapters.suricata import suricata_eve_to_features
from netids.features.schema import SCHEMA_VERSION, validate_feature_matrix
from netids.hybrid_review import evaluate_hybrid
from netids import hybrid_provenance


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


@dataclass
class _PendingRecord:
    event: dict | None
    end_offset: int


class _ReplayEventIndex:
    def __init__(self, worker):
        self.worker = worker

    def __contains__(self, event_id: str) -> bool:
        with self.worker._connect_ledger() as connection:
            return connection.execute("SELECT 1 FROM hybrid_replay WHERE telemetry_event_id = ?", (event_id,)).fetchone() is not None

    def add(self, event_id: str) -> None:
        # The durable insert is committed with the event record.
        return None


class _ReplaySequenceWatermarks:
    def __init__(self, worker):
        self.worker = worker

    def get(self, capture_id: str, default: int = -1) -> int:
        with self.worker._connect_ledger() as connection:
            row = connection.execute("SELECT MAX(sequence) FROM hybrid_replay WHERE capture_run_id = ?", (capture_id,)).fetchone()
        return default if row is None or row[0] is None else int(row[0])

    def __setitem__(self, capture_id: str, sequence: int) -> None:
        return None


class JsonlEveReader:
    """Incrementally read JSONL with bounded buffering and explicit acknowledgements.

    ``offset`` is the committed cursor.  Bytes may be read ahead into the
    bounded pending deque, but a valid record advances ``offset`` only after
    :meth:`acknowledge` succeeds.
    """

    def __init__(self, path: str | Path, *, max_chunk_bytes: int = 64 * 1024,
                 max_line_bytes: int = 1_000_000, dedupe_limit: int = 10_000):
        if max_chunk_bytes < 128 or max_line_bytes < 128 or dedupe_limit < 1:
            raise ValueError("Reader bounds must be positive")
        self.path = Path(path)
        self.max_chunk_bytes = max_chunk_bytes
        self.max_line_bytes = max_line_bytes
        self.dedupe_limit = dedupe_limit
        self.offset = 0
        self._identity: tuple[int, int] | None = None
        self._partial = b""
        self._seen_order: deque[str] = deque(maxlen=dedupe_limit)
        self._seen: set[str] = set()
        self._partial_counted = False
        self._discarding_oversize_line = False
        self._pending: deque[_PendingRecord] = deque()
        self._read_offset = 0
        self.stats = ReaderStats()

    def _reset_for_rotation(self, identity: tuple[int, int]) -> None:
        self.offset = 0
        self._read_offset = 0
        self._partial = b""
        self._partial_counted = False
        self._discarding_oversize_line = False
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

    def read_available(self, *, max_records: int = 1024, max_bytes: int | None = None) -> list[dict]:
        if max_records < 1:
            raise ValueError("max_records must be positive")
        if max_bytes is not None and max_bytes < 1:
            raise ValueError("max_bytes must be positive")
        while self._pending and self._pending[0].event is None:
            self.offset = self._pending.popleft().end_offset
        if self._pending:
            return [item.event for item in list(self._pending)[:max_records] if item.event is not None]
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            return []

        identity = (int(stat.st_dev), int(stat.st_ino))
        if self._identity is None:
            self._identity = identity
        elif identity != self._identity or stat.st_size < self._read_offset:
            self._reset_for_rotation(identity)

        with self.path.open("rb") as stream:
            stream.seek(self._read_offset)
            chunk = stream.read(min(self.max_chunk_bytes, max_bytes) if max_bytes is not None else self.max_chunk_bytes)
            self._read_offset = stream.tell()

        if not chunk:
            return []
        if self._discarding_oversize_line:
            newline = chunk.find(b"\n")
            if newline < 0:
                self.offset = self._read_offset
                return []
            discarded = newline + 1
            self.offset = self._read_offset - len(chunk) + discarded
            chunk = chunk[discarded:]
            self._discarding_oversize_line = False
            self._partial_counted = False
            if not chunk:
                return []
        discarding_before = self._discarding_oversize_line
        data = self._partial + chunk
        base_offset = self._read_offset - len(data)
        lines = data.split(b"\n")
        self._partial = lines.pop()
        if b"\n" in data:
            self._partial_counted = False
        if self._partial and not self._partial_counted and not self._discarding_oversize_line:
            self.stats.incomplete_lines += 1
            self._partial_counted = True
        if len(self._partial) > self.max_line_bytes and not self._discarding_oversize_line:
            self._partial = b""
            self._partial_counted = False
            self._discarding_oversize_line = True
            self.stats.malformed_lines += 1
            self.offset = self._read_offset

        position = base_offset
        for raw in lines:
            end_offset = position + len(raw) + 1
            position = end_offset
            if discarding_before:
                self._discarding_oversize_line = False
                self._partial_counted = False
                self._partial = b""
                continue
            if not raw.strip():
                self._partial_counted = False
                self._pending.append(_PendingRecord(None, end_offset))
                continue
            if len(raw) > self.max_line_bytes:
                self.stats.malformed_lines += 1
                self._pending.append(_PendingRecord(None, end_offset))
                continue
            try:
                event = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self.stats.malformed_lines += 1
                self._pending.append(_PendingRecord(None, end_offset))
                continue
            if not isinstance(event, dict) or not self._remember(self._event_identity(event)):
                if not isinstance(event, dict):
                    self.stats.malformed_lines += 1
                self._pending.append(_PendingRecord(None, end_offset))
                continue
            self._pending.append(_PendingRecord(event, end_offset))
        if not self._partial:
            self._partial_counted = False
        while self._pending and self._pending[0].event is None:
            self.offset = self._pending.popleft().end_offset
        return [item.event for item in list(self._pending)[:max_records] if item.event is not None]

    def acknowledge(self, event: dict) -> None:
        if not self._pending or self._pending[0].event is None:
            raise RuntimeError("No pending event is available to acknowledge")
        if self._event_identity(self._pending[0].event) != self._event_identity(event):
            raise RuntimeError("Events must be acknowledged in file order")
        self.offset = self._pending.popleft().end_offset


@dataclass
class WorkerResult:
    processed_events: int = 0
    rejected_events: int = 0
    evicted_windows: int = 0


class TransientProcessingError(RuntimeError):
    """Processing failed transiently; leave the event unacknowledged for retry."""


class FlowModelAdapter:
    """Inference adapter enforcing the exact EVE flow feature contract."""

    def __init__(self, model, metadata: dict, *, allow_test_model: bool = False):
        if metadata.get("schema_version") != SCHEMA_VERSION:
            raise ValueError("Model schema is not EVE-compatible")
        if metadata.get("feature_columns") != [
            "protocol_tcp", "duration_log", "packets_log", "bytes_log"
        ]:
            raise ValueError("Model feature order mismatch")
        model_sha = metadata.get("model_sha256")
        if not isinstance(model_sha, str) or not re.fullmatch(r"[0-9a-f]{64}", model_sha):
            raise ValueError("Model provenance must contain a verified SHA256")
        if metadata.get("status") == "test_only" and allow_test_model:
            pass
        elif (metadata.get("status") != "verified" or
              not metadata.get("source_dataset") or
              not metadata.get("preprocessing") or
              not metadata.get("threshold_provenance")):
            raise ValueError("Model requires verified production provenance")
        threshold = metadata.get("decision_threshold")
        if not isinstance(threshold, (int, float)) or isinstance(threshold, bool) or not math.isfinite(float(threshold)) or not 0 <= float(threshold) <= 1:
            raise ValueError("Model decision threshold is invalid")
        provenance = metadata.get("threshold_provenance")
        if not isinstance(provenance, dict):
            raise ValueError("Model threshold provenance is invalid")
        if provenance.get("decision_threshold") is not None and float(provenance["decision_threshold"]) != float(threshold):
            raise ValueError("Model threshold provenance mismatch")
        if metadata.get("status") != "test_only":
            required = {"decision_threshold", "calibration_method", "calibration_version", "calibration_manifest_sha256", "status"}
            if set(provenance) != required or provenance.get("status") != "verified" or not isinstance(provenance.get("calibration_method"), str) or not isinstance(provenance.get("calibration_version"), str) or not re.fullmatch(r"[0-9a-f]{64}", str(provenance.get("calibration_manifest_sha256"))):
                raise ValueError("Model threshold provenance is incomplete")
        self.decision_threshold = float(threshold)
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
        return {"features": features, "score": score, "anomalous": score >= self.decision_threshold}


class _WindowAggregator:
    def __init__(self, seconds: int, retention_seconds: int, max_active_windows: int):
        if seconds < 1 or retention_seconds < 0 or max_active_windows < 1:
            raise ValueError("Window seconds must be positive")
        self.seconds = seconds
        self.retention_seconds = retention_seconds
        self.max_active_windows = max_active_windows
        self._windows: dict[tuple[str, int], dict[str, Any]] = {}
        self.evicted_windows = 0
        self._watermark = 0

    @property
    def active_window_count(self) -> int:
        return len(self._windows)

    def _evict_expired(self, watermark: int) -> None:
        expiry = watermark - self.retention_seconds
        expired = [key for key in self._windows if key[3] + self.seconds <= expiry]
        for key in expired:
            del self._windows[key]
        self.evicted_windows += len(expired)

    def _enforce_capacity(self) -> None:
        while len(self._windows) > self.max_active_windows:
            oldest = min(self._windows, key=lambda key: key[3])
            del self._windows[oldest]
            self.evicted_windows += 1

    def add(self, event: dict, score: float, anomalous: bool) -> dict:
        timestamp = _event_time(event)
        epoch = int(timestamp.timestamp())
        self._watermark = max(self._watermark, epoch)
        self._evict_expired(self._watermark)
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
        self._enforce_capacity()
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
                 run_id: str, window_seconds: int = 10, max_bytes_per_cycle: int = 4 * 1024 * 1024,
                 max_records_per_cycle: int = 1024, processing_time_budget_seconds: float | None = None,
                 window_retention_seconds: int | None = None, max_active_windows: int = 10_000,
                 ledger_path: str | Path | None = None, output_max_records: int = 10_000):
        if (not run_id.strip() or max_bytes_per_cycle < 1 or max_records_per_cycle < 1 or
                (processing_time_budget_seconds is not None and processing_time_budget_seconds <= 0) or
                output_max_records < 1):
            raise ValueError("run_id and cycle bounds are required")
        self.reader = reader
        self.model = model
        self.output_path = Path(output_path)
        self.run_id = run_id
        self.max_bytes_per_cycle = max_bytes_per_cycle
        self.max_records_per_cycle = max_records_per_cycle
        self.processing_time_budget_seconds = processing_time_budget_seconds
        self.ledger_path = Path(ledger_path) if ledger_path is not None else self.output_path.with_suffix(".ledger.sqlite3")
        self.output_max_records = output_max_records
        self._windows = _WindowAggregator(
            window_seconds,
            window_seconds if window_retention_seconds is None else window_retention_seconds,
            max_active_windows,
        )
        self._stop = threading.Event()
        self._output_lock = threading.Lock()
        self._rejected = 0
        self._seen_capture_ids = _ReplayEventIndex(self)
        self._last_hybrid_sequences = _ReplaySequenceWatermarks(self)
        self._initialize_ledger()
        self._restore_source_cursor()
        self.projection_rebuilds = 0
        self.projection_writes = 0
        self.projection_rotations = 0
        self._projection_count = 0
        self._rebuild_output_projection()

    @property
    def active_window_count(self) -> int:
        return self._windows.active_window_count

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
        try:
            evidence = hybrid_provenance.verify_envelope(
                telemetry, expected_run_id=self.run_id, event_time=_event_time(event),
                seen_capture_ids=self._seen_capture_ids, last_sequences=self._last_hybrid_sequences,
            )
        except ValueError:
            return {"schema_version": "hybrid_review_v1", "classification": "unavailable_invalid_telemetry_provenance",
                    "requires_manual_review": True, "approved": False, "deployable": False}
        decision = evaluate_hybrid(
            ml_consensus=anomalous,
            rst_evidence=evidence["rst_evidence"],
            port_evidence=evidence["port_evidence"],
            handshake_evidence=evidence["handshake_evidence"],
            thresholds=evidence["thresholds"],
        )
        return {
            **decision,
            "capture_run_id": telemetry["capture_run_id"],
            "telemetry_event_id": telemetry["telemetry_event_id"],
            "sequence": telemetry["sequence"],
            "producer_key_sha256": telemetry["producer_key_sha256"],
        }

    def _connect_ledger(self):
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.ledger_path)
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    def _initialize_ledger(self) -> None:
        with self._connect_ledger() as connection:
            connection.execute("CREATE TABLE IF NOT EXISTS events (detection_id TEXT PRIMARY KEY, event_sha256 TEXT NOT NULL, record_json TEXT NOT NULL, created_utc REAL NOT NULL)")
            connection.execute("CREATE TABLE IF NOT EXISTS hybrid_replay (capture_run_id TEXT NOT NULL, telemetry_event_id TEXT PRIMARY KEY, sequence INTEGER NOT NULL, producer_key_sha256 TEXT NOT NULL)")
            connection.execute("CREATE TABLE IF NOT EXISTS source_cursor (source_path TEXT PRIMARY KEY, device TEXT NOT NULL, inode TEXT NOT NULL, committed_offset INTEGER NOT NULL)")

    def _restore_source_cursor(self) -> None:
        try:
            stat = self.reader.path.stat()
        except FileNotFoundError:
            return
        with self._connect_ledger() as connection:
            row = connection.execute("SELECT device, inode, committed_offset FROM source_cursor WHERE source_path = ?", (str(self.reader.path),)).fetchone()
        if row and str(row[0]) == str(stat.st_dev) and str(row[1]) == str(stat.st_ino) and 0 <= row[2] <= stat.st_size:
            self.reader.offset = row[2]
            self.reader._read_offset = row[2]
            self.reader._identity = (int(row[0]), int(row[1]))

    def _acknowledge(self, event: dict) -> None:
        self.reader.acknowledge(event)
        try:
            stat = self.reader.path.stat()
        except FileNotFoundError:
            return
        with self._connect_ledger() as connection:
            connection.execute(
                "INSERT INTO source_cursor(source_path, device, inode, committed_offset) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(source_path) DO UPDATE SET device=excluded.device, inode=excluded.inode, committed_offset=excluded.committed_offset",
                (str(self.reader.path), str(stat.st_dev), str(stat.st_ino), self.reader.offset),
            )

    def _ledger_contains(self, detection_id: str) -> bool:
        with self._connect_ledger() as connection:
            return connection.execute("SELECT 1 FROM events WHERE detection_id = ?", (detection_id,)).fetchone() is not None

    def _rebuild_output_projection(self) -> None:
        with self._connect_ledger() as connection:
            rows = connection.execute("SELECT record_json FROM events ORDER BY created_utc DESC LIMIT ?", (self.output_max_records,)).fetchall()
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        with self.output_path.open("w", encoding="utf-8") as stream:
            for (record_json,) in reversed(rows):
                stream.write(record_json + "\n")
        self._projection_count = len(rows)
        self.projection_rebuilds += 1

    def _append_projection(self, record: dict) -> None:
        if self._projection_count >= self.output_max_records:
            archive = self.output_path.with_name(self.output_path.name + ".1")
            if self.output_path.exists():
                os.replace(self.output_path, archive)
            self._projection_count = 0
            self.projection_rotations += 1
        with self._output_lock, self.output_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")
        self._projection_count += 1
        self.projection_writes += 1

    def _commit_record(self, record: dict) -> bool:
        detection_id = record["detection_id"]
        event_sha = record["provenance"]["event_sha256"]
        with self._connect_ledger() as connection:
            inserted = connection.execute(
                "INSERT OR IGNORE INTO events(detection_id, event_sha256, record_json, created_utc) VALUES (?, ?, ?, ?)",
                (detection_id, event_sha, json.dumps(record, sort_keys=True, ensure_ascii=False), time.time()),
            ).rowcount
            if not inserted:
                return False
            hybrid = record.get("hybrid", {})
            if hybrid.get("telemetry_event_id"):
                connection.execute(
                    "INSERT OR IGNORE INTO hybrid_replay(capture_run_id, telemetry_event_id, sequence, producer_key_sha256) VALUES (?, ?, ?, ?)",
                    (hybrid["capture_run_id"], hybrid["telemetry_event_id"], hybrid["sequence"], hybrid["producer_key_sha256"]),
                )
        self._append_projection(record)
        return True

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
        self._commit_record(record)

    def _detection_id(self, event: dict) -> str:
        return hashlib.sha256(f"{self.run_id}:{_canonical_sha256(event)}".encode()).hexdigest()

    def run_once(self) -> WorkerResult:
        result = WorkerResult()
        started = time.monotonic()
        cycle_start = self.reader._read_offset
        while (not self._stop.is_set() and
               result.processed_events + result.rejected_events < self.max_records_per_cycle and
               self.reader._read_offset - cycle_start < self.max_bytes_per_cycle and
               (self.processing_time_budget_seconds is None or
                time.monotonic() - started < self.processing_time_budget_seconds)):
            remaining = self.max_records_per_cycle - result.processed_events - result.rejected_events
            remaining_bytes = self.max_bytes_per_cycle - (self.reader._read_offset - cycle_start)
            batch = self.reader.read_available(max_records=remaining, max_bytes=remaining_bytes)
            if not batch:
                try:
                    size = self.reader.path.stat().st_size
                except FileNotFoundError:
                    size = self.reader._read_offset
                if self.reader._read_offset >= size:
                    break
                continue
            for event in batch:
                if (self._stop.is_set() or
                        (self.processing_time_budget_seconds is not None and
                         time.monotonic() - started >= self.processing_time_budget_seconds)):
                    break
                if self._ledger_contains(self._detection_id(event)):
                    self._acknowledge(event)
                    continue
                try:
                    self._process(event)
                    self._acknowledge(event)
                    result.processed_events += 1
                except (KeyError, TypeError, ValueError, OverflowError):
                    self._rejected += 1
                    self._acknowledge(event)
                    result.rejected_events += 1
                except TransientProcessingError:
                    return result
        result.evicted_windows = self._windows.evicted_windows
        return result

    def run_forever(self, *, poll_interval: float = 0.25) -> str:
        if poll_interval < 0:
            raise ValueError("poll_interval cannot be negative")
        while not self._stop.is_set():
            self.run_once()
            if poll_interval:
                self._stop.wait(poll_interval)
        return "shutdown"
