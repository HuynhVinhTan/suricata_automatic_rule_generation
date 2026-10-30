import math
from datetime import datetime


def extract_duration(event: dict) -> float:
    flow = event["flow"]

    start = datetime.fromisoformat(flow["start"])
    end = datetime.fromisoformat(flow["end"])

    if start.utcoffset() is None or end.utcoffset() is None:
        raise ValueError("Flow timestamps must include timezone")

    duration = (end - start).total_seconds()

    if duration < 0:
        raise ValueError("Flow end cannot be earlier than start")

    return duration


# đọc và xác minh dữ liệu gốc.
def extract_flow_counters(event: dict) -> dict:
    flow = event["flow"]

    fields = [
        "pkts_toserver",
        "pkts_toclient",
        "bytes_toserver",
        "bytes_toclient",
    ]

    counters = {}

    for field in fields:
        value = flow[field]

        if type(value) is not int:
            raise TypeError(f"{field} must be an integer")

        if value < 0:
            raise ValueError(f"{field} cannot be negative")

        counters[field] = value

    return counters


# tính các feature mới từ dữ liệu đã xác minh.
def derive_flow_totals(counters: dict) -> dict:
    total_packets = (
        counters["pkts_toserver"]
        + counters["pkts_toclient"]
    )

    total_bytes = (
        counters["bytes_toserver"]
        + counters["bytes_toclient"]
    )

    return {
        "total_packets": total_packets,
        "total_bytes": total_bytes,
    }


# kiểm tra duration có phải số hữu hạn không, tránh NaN và vô cực.
def derive_flow_rates(totals: dict, duration: float) -> dict:
    if not math.isfinite(duration) or duration < 0:
        raise ValueError("Invalid duration")

    if duration == 0:
        return {
            "packets_per_second": None,
            "bytes_per_second": None,
        }

    return {
        "packets_per_second": totals["total_packets"] / duration,
        "bytes_per_second": totals["total_bytes"] / duration,
    }


# Function Composition: Kết hợp nhiều hàm nhỏ thành một chức năng lớn.
def extract_flow_features(event: dict) -> dict:
    duration = extract_duration(event)          # Kiểm tra thời lượng
    counters = extract_flow_counters(event)     # Kiểm tra bộ đếm
    totals = derive_flow_totals(counters)       # Tính tổng total_packets và total_bytes
    rates = derive_flow_rates(totals, duration) # Tính tốc độ.

    return {
        "duration_seconds": duration,
        **counters,
        **totals,
        **rates,
    }

"""Suricata EVE flow adapter for Feature Schema v0.1.

This is a candidate feature mapping.
Equivalence with CTU-13 Argus counters is not yet verified.
"""

from collections.abc import Mapping
from datetime import datetime
from math import log1p


FEATURE_NAMES = (
    "protocol_tcp",
    "duration_log",
    "packets_log",
    "bytes_log",
)


def _parse_timestamp(value, field_name):
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a timestamp string")

    try:
        timestamp = datetime.fromisoformat(
            value.strip().replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise ValueError(
            f"Invalid timestamp: {field_name}"
        ) from exc

    if timestamp.utcoffset() is None:
        raise ValueError(
            f"{field_name} must include a timezone"
        )

    return timestamp


def _read_counter(flow, name):
    if name not in flow:
        raise ValueError(f"Missing EVE counter: {name}")

    value = flow[name]

    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
    ):
        raise ValueError(
            f"{name} must be a non-negative integer"
        )

    return value


def suricata_eve_to_features(event):
    """Convert one completed EVE flow event to four ML features.

    No inference is performed.
    No source/destination IP is returned.
    """

    if not isinstance(event, Mapping):
        raise ValueError("EVE event must be an object")

    if event.get("event_type") != "flow":
        raise ValueError("Only EVE flow events are supported")

    proto = str(event.get("proto", "")).strip().upper()

    if proto not in {"TCP", "UDP"}:
        raise ValueError(
            f"Unsupported EVE protocol: {proto}"
        )

    flow = event.get("flow")

    if not isinstance(flow, Mapping):
        raise ValueError("Missing or invalid EVE flow object")

    start = _parse_timestamp(
        flow.get("start"),
        "flow.start",
    )

    end = _parse_timestamp(
        flow.get("end"),
        "flow.end",
    )

    duration_s = (end - start).total_seconds()

    if duration_s < 0:
        raise ValueError("Flow end precedes flow start")

    packets_total = (
        _read_counter(flow, "pkts_toserver")
        + _read_counter(flow, "pkts_toclient")
    )

    bytes_total = (
        _read_counter(flow, "bytes_toserver")
        + _read_counter(flow, "bytes_toclient")
    )

    return {
        "protocol_tcp": 1 if proto == "TCP" else 0,
        "duration_log": log1p(duration_s),
        "packets_log": log1p(packets_total),
        "bytes_log": log1p(bytes_total),
    }