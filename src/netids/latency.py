"""Small, monotonic stage timer for reproducible experiment latency records.

The timer deliberately separates monotonic elapsed time from UTC wall-clock
timestamps.  Wall-clock values are useful for correlating logs; elapsed values
are the measurement and must not be reconstructed from UTC timestamps.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import math
import time
from typing import Iterator


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class LatencyTrace:
    """Collect named, non-overlapping or nested stage measurements."""

    def __init__(self, *, run_id: str, host: str | None = None, clock_sync: dict | None = None):
        if not isinstance(run_id, str) or not run_id.strip():
            raise ValueError("run_id must be a non-empty string")
        if host is not None and (not isinstance(host, str) or not host.strip()):
            raise ValueError("host must be a non-empty string when provided")
        if clock_sync is not None and not isinstance(clock_sync, dict):
            raise ValueError("clock_sync must be an object when provided")
        self.run_id = run_id
        self.host = host
        self.clock_sync = dict(clock_sync) if clock_sync is not None else None
        self.started_at_utc = _utc_now()
        self._active: dict[str, tuple[int, str]] = {}
        self.stages: list[dict] = []

    @contextmanager
    def stage(self, name: str, *, component: str | None = None) -> Iterator[None]:
        """Measure a stage and preserve failure timing before re-raising."""
        if not isinstance(name, str) or not name.strip():
            raise ValueError("stage name must be a non-empty string")
        if component is not None and (not isinstance(component, str) or not component.strip()):
            raise ValueError("component must be a non-empty string when provided")
        if name in self._active:
            raise ValueError(f"stage already active: {name}")
        start_ns = time.perf_counter_ns()
        self._active[name] = (start_ns, _utc_now())
        status = "success"
        error = None
        try:
            yield
        except Exception as exc:
            status = "error"
            error = type(exc).__name__
            raise
        finally:
            started_ns, started_at = self._active.pop(name)
            ended_ns = time.perf_counter_ns()
            entry = {
                "name": name,
                "started_at_utc": started_at,
                "ended_at_utc": _utc_now(),
                "elapsed_ms": round((ended_ns - started_ns) / 1_000_000, 3),
                "status": status,
                "clock_type": "monotonic",
            }
            if component is not None:
                entry["component"] = component
            if error:
                entry["error_type"] = error
            self.stages.append(entry)

    def record(
        self,
        name: str,
        elapsed_ms: float | None = None,
        *,
        status: str = "measured",
        component: str | None = None,
        clock_type: str = "external",
    ) -> None:
        """Record an external stage; unmeasured stages have no duration field."""
        if not isinstance(name, str) or not name.strip():
            raise ValueError("stage name must be a non-empty string")
        if component is not None and (not isinstance(component, str) or not component.strip()):
            raise ValueError("component must be a non-empty string when provided")
        if not isinstance(clock_type, str) or not clock_type.strip():
            raise ValueError("clock_type must be a non-empty string")
        if status == "not_measured":
            if elapsed_ms is not None:
                raise ValueError("not_measured stages cannot contain elapsed_ms")
        elif not isinstance(elapsed_ms, (int, float)) or elapsed_ms < 0:
            raise ValueError("measured stages require a non-negative elapsed_ms")
        entry = {
            "name": name,
            "status": status,
            "timestamp_source": "external_measurement",
            "clock_type": clock_type,
        }
        if component is not None:
            entry["component"] = component
        if elapsed_ms is not None:
            entry["elapsed_ms"] = round(float(elapsed_ms), 3)
        self.stages.append(entry)

    def as_dict(self) -> dict:
        if self._active:
            raise ValueError("cannot serialize a trace with active stages")
        result = {
            "schema_version": "latency_trace_v1",
            "run_id": self.run_id,
            "started_at_utc": self.started_at_utc,
            "stages": list(self.stages),
        }
        if self.host is not None or self.clock_sync is not None:
            result["clock"] = {
                "host": self.host,
                "elapsed_clock": "monotonic",
                "wall_clock": "UTC",
                "synchronization": self.clock_sync or {"status": "not_recorded"},
            }
        return result


def _validate_utc_timestamp(value: object, field: str) -> None:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be an ISO-8601 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{field} is invalid") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a timezone")


def validate_latency_trace(trace: dict, *, expected_run_id: str | None = None) -> None:
    """Validate trace identity, clocks and durations without deriving wall time."""
    if not isinstance(trace, dict) or trace.get("schema_version") != "latency_trace_v1":
        raise ValueError("unsupported latency trace schema")
    run_id = trace.get("run_id")
    if not isinstance(run_id, str) or not run_id.strip():
        raise ValueError("latency trace run_id is missing")
    if expected_run_id is not None and run_id != expected_run_id:
        raise ValueError("latency trace run_id does not match evidence run_id")
    _validate_utc_timestamp(trace.get("started_at_utc"), "latency trace started_at_utc")
    clock = trace.get("clock")
    if clock is not None:
        if not isinstance(clock, dict):
            raise ValueError("latency trace clock is invalid")
        if clock.get("host") is not None and (
            not isinstance(clock["host"], str) or not clock["host"].strip()
        ):
            raise ValueError("latency trace clock host is invalid")
        if clock.get("elapsed_clock") != "monotonic" or clock.get("wall_clock") != "UTC":
            raise ValueError("latency trace clock type is invalid")
        synchronization = clock.get("synchronization")
        if not isinstance(synchronization, dict) or not isinstance(
            synchronization.get("status"), str
        ):
            raise ValueError("latency trace clock synchronization is invalid")
        if "offset_ms" in synchronization and (
            not isinstance(synchronization["offset_ms"], (int, float))
            or isinstance(synchronization["offset_ms"], bool)
            or not math.isfinite(float(synchronization["offset_ms"]))
        ):
            raise ValueError("latency trace clock offset is invalid")
    stages = trace.get("stages")
    if not isinstance(stages, list):
        raise ValueError("latency trace stages are missing")
    for stage in stages:
        if not isinstance(stage, dict) or not isinstance(stage.get("name"), str) or not stage["name"].strip():
            raise ValueError("latency trace stage name is invalid")
        status = stage.get("status")
        if not isinstance(status, str) or not status.strip():
            raise ValueError("latency trace stage status is invalid")
        if "elapsed_ms" in stage:
            elapsed = stage["elapsed_ms"]
            if (
                not isinstance(elapsed, (int, float))
                or isinstance(elapsed, bool)
                or not math.isfinite(float(elapsed))
                or elapsed < 0
            ):
                raise ValueError("latency trace elapsed_ms is invalid")
        if ("started_at_utc" in stage) != ("ended_at_utc" in stage):
            raise ValueError("latency trace stage timestamps are incomplete")
        if "started_at_utc" in stage:
            _validate_utc_timestamp(stage["started_at_utc"], "latency stage started_at_utc")
            _validate_utc_timestamp(stage["ended_at_utc"], "latency stage ended_at_utc")
        clock_type = stage.get("clock_type")
        if clock_type is not None and (not isinstance(clock_type, str) or not clock_type.strip()):
            raise ValueError("latency trace stage clock_type is invalid")
