"""Small, monotonic stage timer for reproducible experiment latency records.

The timer deliberately separates monotonic elapsed time from UTC wall-clock
timestamps.  Wall-clock values are useful for correlating logs; elapsed values
are the measurement and must not be reconstructed from UTC timestamps.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import time
from typing import Iterator


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class LatencyTrace:
    """Collect named, non-overlapping or nested stage measurements."""

    def __init__(self, *, run_id: str):
        if not isinstance(run_id, str) or not run_id.strip():
            raise ValueError("run_id must be a non-empty string")
        self.run_id = run_id
        self.started_at_utc = _utc_now()
        self._active: dict[str, tuple[int, str]] = {}
        self.stages: list[dict] = []

    @contextmanager
    def stage(self, name: str) -> Iterator[None]:
        """Measure a stage and preserve failure timing before re-raising."""
        if not isinstance(name, str) or not name.strip():
            raise ValueError("stage name must be a non-empty string")
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
            self.stages.append({
                "name": name,
                "started_at_utc": started_at,
                "ended_at_utc": _utc_now(),
                "elapsed_ms": round((ended_ns - started_ns) / 1_000_000, 3),
                "status": status,
                **({"error_type": error} if error else {}),
            })

    def record(self, name: str, elapsed_ms: float, *, status: str = "measured") -> None:
        """Record an externally measured stage without inventing timestamps."""
        if not isinstance(elapsed_ms, (int, float)) or elapsed_ms < 0:
            raise ValueError("elapsed_ms must be a non-negative number")
        self.stages.append({
            "name": name,
            "elapsed_ms": round(float(elapsed_ms), 3),
            "status": status,
            "timestamp_source": "external_measurement",
        })

    def as_dict(self) -> dict:
        if self._active:
            raise ValueError("cannot serialize a trace with active stages")
        return {
            "schema_version": "latency_trace_v1",
            "run_id": self.run_id,
            "started_at_utc": self.started_at_utc,
            "stages": list(self.stages),
        }
