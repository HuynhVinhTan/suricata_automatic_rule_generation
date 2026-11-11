"""Build review-only correlation envelopes from existing private lab artifacts."""

import argparse
import hashlib
import json
import struct
from datetime import datetime
from pathlib import Path

from netids.correlation import build_correlation_envelope


def pcap_flows(path):
    raw = path.read_bytes()
    magic = raw[:4]
    endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    nanoseconds = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    offset, flows, timestamps = 24, set(), []
    while offset + 16 <= len(raw):
        sec, fraction, length, _ = struct.unpack_from(
            endian + "IIII", raw, offset
        )
        offset += 16
        packet = raw[offset : offset + length]
        offset += length
        timestamps.append(sec + fraction / (1e9 if nanoseconds else 1e6))
        if len(packet) < 54 or packet[14] >> 4 != 4 or packet[23] != 6:
            continue
        ip_length = (packet[14] & 15) * 4
        tcp = 14 + ip_length
        if len(packet) < tcp + 4:
            continue
        source = ".".join(map(str, packet[26:30]))
        destination = ".".join(map(str, packet[30:34]))
        source_port, destination_port = struct.unpack_from("!HH", packet, tcp)
        flows.add(tuple(sorted(((source, source_port), (destination, destination_port)))))
    return flows, min(timestamps), max(timestamps)


def event_matches(event, flows, start, end):
    fields = ("src_ip", "src_port", "dest_ip", "dest_port", "timestamp")
    if any(field not in event for field in fields):
        return False
    key = tuple(sorted(((event["src_ip"], event["src_port"]),
                        (event["dest_ip"], event["dest_port"]))))
    try:
        stamp = datetime.fromisoformat(
            event["timestamp"].replace("+0000", "+00:00")
        ).timestamp()
    except (TypeError, ValueError):
        return False
    return key in flows and start - 1 <= stamp <= end + 1


def build_records(private_root, eve_root, calibration_sha256, rule_sha256):
    holdouts = Path(private_root) / "fresh-holdouts-20261111"
    records = []
    for directory in sorted(holdouts.iterdir()):
        evidence_path = directory / "evidence-manifest.json"
        worker_manifest = json.loads((directory / "worker-manifest.json").read_text())
        evidence = json.loads(evidence_path.read_text())
        run_id = worker_manifest["run_id"]
        summary_path = Path(private_root) / "lab-runs" / run_id / "worker_summary.json"
        summary = json.loads(summary_path.read_text())
        review_path = (
            Path(private_root) / "lab-runs" /
            ("fresh-" + directory.name + "-20261111") / "review.json"
        )
        review = json.loads(review_path.read_text())
        eve_path = Path(eve_root) / directory.name / "suricata.eve.json"
        eve_events = [json.loads(line) for line in eve_path.read_text().splitlines() if line]
        flows, start, end = pcap_flows(directory / "traffic.pcap")
        matching_events = [event for event in eve_events if event_matches(event, flows, start, end)]
        matching_flows = {
            tuple(sorted(((event["src_ip"], event["src_port"]),
                          (event["dest_ip"], event["dest_port"]))))
            for event in eve_events
            if event.get("event_type") == "flow" and event_matches(event, flows, start, end)
        }
        classification = review["hybrid_review"]["classification"]
        record = build_correlation_envelope(
            run_id=run_id,
            scenario=directory.name.split("-", 1)[0],
            pcap_sha256=worker_manifest["pcap_sha256"],
            manifest_sha256=hashlib.sha256(evidence_path.read_bytes()).hexdigest(),
            eve_output_sha256=hashlib.sha256(eve_path.read_bytes()).hexdigest(),
            model_sha256=summary["model_sha256"],
            calibration_sha256=calibration_sha256,
            ai_summary_document_id=hashlib.sha256(run_id.encode()).hexdigest(),
            ai_summary_sha256=hashlib.sha256(summary_path.read_bytes()).hexdigest(),
            suricata_version="8.0.3",
            replay_rule_sha256=rule_sha256,
            matched_eve_events=len(matching_events),
            matched_flows=len(matching_flows),
            hybrid_classification=classification,
            review_status=summary["review_status"],
            sid=9103003,
            correlation_level="event_verified",
        )
        record.update({
            "document_id": hashlib.sha256(
                f"{run_id}:{worker_manifest['pcap_sha256']}".encode()
            ).hexdigest(),
            "ai_summary_indexed": False,
            "native_eve_preserved": True,
            "correlation_status": "event_verified_ai_summary_artifact_not_indexed",
        })
        records.append(record)
    return records


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--private-root", type=Path, default=Path("data/private"))
    parser.add_argument("--eve-root", type=Path, required=True)
    parser.add_argument("--calibration-sha256", required=True)
    parser.add_argument("--rule-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    records = build_records(
        args.private_root, args.eve_root, args.calibration_sha256, args.rule_sha256
    )
    args.output.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(records, indent=2))


if __name__ == "__main__":
    main()
