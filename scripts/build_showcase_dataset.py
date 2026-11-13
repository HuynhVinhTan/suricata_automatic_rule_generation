"""Correlate labelled lab manifests to exact Suricata EVE flow tuples."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from netids.adapters.suricata import suricata_eve_to_features

FLOW_COMPLETION_GRACE_SECONDS = 2

def _time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _event_sha256(event: dict) -> str:
    return hashlib.sha256(json.dumps(event, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def correlate_sessions(manifests: list[dict], events: list[dict]) -> list[dict]:
    rows = []
    for manifest in manifests:
        for attempt in manifest.get("attempts", []):
            start = _time(attempt["timestamp_utc"])
            end = _time(attempt.get("attempt_end_utc", attempt["timestamp_utc"]))
            bounded_end = end.timestamp() + FLOW_COMPLETION_GRACE_SECONDS
            matches = []
            for event in events:
                if event.get("event_type") != "flow":
                    continue
                if (event.get("src_ip"), int(event.get("src_port", -1)), event.get("dest_ip"), int(event.get("dest_port", -1)), str(event.get("proto", "")).upper()) != (
                    attempt["source_ip"], int(attempt["source_port"]), attempt["target_ip"], int(attempt["destination_port"]), str(attempt["protocol"]).upper()):
                    continue
                flow_start = _time(event["flow"]["start"])
                flow_end = _time(event["flow"].get("end", event["flow"]["start"]))
                if start.timestamp() <= flow_start.timestamp() <= bounded_end and flow_end.timestamp() <= bounded_end:
                    matches.append(event)
            if len(matches) != 1:
                continue
            event = matches[0]
            result = attempt.get("result")
            http_status = attempt.get("http_status")
            if manifest["scenario"] == "ATTACK" and result == "rst_refused":
                label, category, eligible = 1, "binary_attack", True
            elif manifest["scenario"] == "NORMAL" and result == "http_200" and http_status == 200:
                label, category, eligible = 0, "binary_normal", True
            elif manifest["scenario"] == "NORMAL" and result == "rst_refused":
                label, category, eligible = None, "negative_control", False
            else:
                label, category, eligible = None, "unexpected", False
            rows.append({
                "run_id": manifest["run_id"], "attempt_id": attempt["attempt_id"],
                "scenario": manifest["scenario"], "result": result, "http_status": http_status,
                "label": label, "category": category, "binary_eligible": eligible,
                "eve_flow_id": event.get("flow_id"), "event_sha256": _event_sha256(event),
                "five_tuple": {"src_ip": event.get("src_ip"), "src_port": event.get("src_port"),
                               "dest_ip": event.get("dest_ip"), "dest_port": event.get("dest_port"),
                               "proto": event.get("proto")},
                "event": event, "features": suricata_eve_to_features(event),
            })
    return rows


def load_jsonl(paths: list[Path]) -> list[dict]:
    events = []
    for path in paths:
        with path.open(encoding="utf-8") as stream:
            for line in stream:
                if line.strip():
                    events.append(json.loads(line))
    return events


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifests", nargs="+", type=Path, required=True)
    parser.add_argument("--eve", nargs="+", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    manifests = [json.loads(path.read_text(encoding="utf-8")) for path in args.manifests]
    rows = correlate_sessions(manifests, load_jsonl(args.eve))
    args.out.mkdir(parents=True, exist_ok=False)
    (args.out / "records.jsonl").write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
    manifest = {"records": len(rows), "runs": sorted({row["run_id"] for row in rows}),
                "category_counts": {category: sum(row["category"] == category for row in rows) for category in sorted({row["category"] for row in rows})},
                "sha256": hashlib.sha256((args.out / "records.jsonl").read_bytes()).hexdigest()}
    (args.out / "dataset.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, sort_keys=True))


if __name__ == "__main__":
    main()
