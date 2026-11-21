import hashlib
import json
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from scripts.verify_attack_evidence import verify_attack_evidence


SRC = "192.168.10.20"
DST = "192.168.10.10"
PORTS = list(range(18100, 18124))
BASE = datetime(2026, 11, 21, 3, 0, tzinfo=timezone.utc)


def _ip(value):
    return bytes(int(part) for part in value.split("."))


def _tcp(src_port, dst_port, flags):
    return struct.pack("!HHIIBBHHH", src_port, dst_port, 0, 0, 5 << 4, flags, 65535, 0, 0)


def _packet(src, dst, src_port, dst_port, flags):
    tcp = _tcp(src_port, dst_port, flags)
    total = 20 + len(tcp)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, 6, 0, _ip(src), _ip(dst))
    eth = b"\x00" * 12 + b"\x08\x00"
    return eth + ip + tcp


def _write_pcap(path, packets):
    with path.open("wb") as stream:
        stream.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 96, 1))
        for timestamp, payload in packets:
            seconds = int(timestamp.timestamp())
            micros = timestamp.microsecond
            stream.write(struct.pack("<IIII", seconds, micros, len(payload), len(payload)))
            stream.write(payload)


def _manifest(source_ports=None, started=BASE, ended=None):
    ended = ended or BASE + timedelta(seconds=48)
    source_ports = source_ports or [40000 + i for i in range(24)]
    attempts = []
    for index, port in enumerate(PORTS):
        attempts.append({
            "timestamp_utc": (BASE + timedelta(seconds=index * 2)).isoformat().replace("+00:00", "Z"),
            "source_port": source_ports[index],
            "target_ip": DST,
            "destination_port": port,
            "result": "rst_refused",
        })
    return {
        "schema_version": "lab_slow_port_scan_v1",
        "scenario": "ATTACK",
        "run_id": "test-attack",
        "source_ip": SRC,
        "target_ip": DST,
        "started_at_utc": started.isoformat().replace("+00:00", "Z"),
        "ended_at_utc": ended.isoformat().replace("+00:00", "Z"),
        "attempt_count": 24,
        "attempts": attempts,
    }


def _evidence(tmp_path, manifest=None, packets=None):
    manifest = manifest or _manifest()
    if packets is None:
        packets = [
            (BASE + timedelta(seconds=i * 2), _packet(SRC, DST, 40000 + i, PORTS[i], 0x02))
            for i in range(24)
        ] + [
            (BASE + timedelta(seconds=i * 2, milliseconds=1), _packet(DST, SRC, PORTS[i], 40000 + i, 0x04))
            for i in range(24)
        ]
    pcap = tmp_path / "attack.pcap"
    manifest_path = tmp_path / "attack.json"
    _write_pcap(pcap, packets)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return pcap, manifest_path


def test_complete_attack_capture_is_verified(tmp_path):
    pcap, manifest = _evidence(tmp_path)

    report = verify_attack_evidence(pcap, manifest)

    assert report["status"] == "PASS"
    assert report["pcap"]["packet_count"] == 48
    assert report["attack"]["distinct_destination_ports"] == PORTS
    assert report["attack"]["matched_attempts"] == 24
    assert report["attack"]["matched_rst_responses"] == 24
    assert report["attack"]["duplicate_syn_packets"] == 0
    assert len(report["pcap"]["sha256"]) == 64


def test_capture_ending_before_attack_is_blocked(tmp_path):
    pcap, manifest = _evidence(tmp_path, packets=[
        (BASE - timedelta(seconds=2), _packet(SRC, DST, 39999, 18099, 0x02)),
    ])

    report = verify_attack_evidence(pcap, manifest)

    assert report["status"] == "BLOCKED"
    assert any("matched" in issue.lower() or "window" in issue.lower() for issue in report["issues"])


def test_normal_rst_controls_are_not_attack_matches(tmp_path):
    packets = [
        (BASE + timedelta(seconds=1), _packet(SRC, DST, 41000, 18100, 0x02)),
        (BASE + timedelta(seconds=1, milliseconds=1), _packet(DST, SRC, 18100, 41000, 0x04)),
    ]
    pcap, manifest = _evidence(tmp_path, packets=packets)

    report = verify_attack_evidence(pcap, manifest)

    assert report["status"] == "BLOCKED"
    assert report["attack"]["matched_attempts"] == 0
    assert report["attack"]["matched_rst_responses"] == 0


def test_missing_rst_and_duplicate_syn_are_reported(tmp_path):
    packets = []
    for i, port in enumerate(PORTS):
        syn = _packet(SRC, DST, 40000 + i, port, 0x02)
        packets.append((BASE + timedelta(seconds=i * 2), syn))
        if i == 0:
            packets.append((BASE + timedelta(seconds=i * 2, milliseconds=10), syn))
        if i != 23:
            packets.append((BASE + timedelta(seconds=i * 2, milliseconds=1), _packet(DST, SRC, port, 40000 + i, 0x04)))
    pcap, manifest = _evidence(tmp_path, packets=packets)

    report = verify_attack_evidence(pcap, manifest)

    assert report["status"] == "BLOCKED"
    assert report["attack"]["duplicate_syn_packets"] == 1
    assert report["attack"]["matched_rst_responses"] == 23
    assert 18123 in report["attack"]["missing_rst_ports"]


@pytest.mark.parametrize(
    "mutate",
    [
        lambda m: m["attempts"][0].update({"source_port": 49999}),
        lambda m: m["attempts"][0].update({"destination_port": 19000}),
        lambda m: m.update({"source_ip": "192.168.10.30"}),
    ],
)
def test_wrong_manifest_scope_is_reported(tmp_path, mutate):
    manifest = _manifest()
    mutate(manifest)
    pcap, manifest_path = _evidence(tmp_path, manifest=manifest)

    report = verify_attack_evidence(pcap, manifest_path)

    assert report["status"] == "BLOCKED"
    assert report["issues"]


def test_timezone_normalization_and_hash_mismatch_are_reported(tmp_path):
    manifest = _manifest(
        started=datetime(2026, 11, 20, 21, 0, tzinfo=timezone(timedelta(hours=-6))),
        ended=datetime(2026, 11, 20, 21, 1, tzinfo=timezone(timedelta(hours=-6))),
    )
    pcap, manifest_path = _evidence(tmp_path, manifest=manifest)
    report = verify_attack_evidence(pcap, manifest_path, expected_sha256="0" * 64)

    assert report["status"] == "BLOCKED"
    assert any("sha256" in issue.lower() for issue in report["issues"])
    assert report["manifest"]["started_at_utc"].endswith("Z")


def test_invalid_truncated_pcap_is_reported(tmp_path):
    pcap = tmp_path / "broken.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"broken")
    manifest = tmp_path / "attack.json"
    manifest.write_text(json.dumps(_manifest()), encoding="utf-8")

    report = verify_attack_evidence(pcap, manifest)

    assert report["status"] == "BLOCKED"
    assert any("pcap" in issue.lower() for issue in report["issues"])


def test_truncated_ipv4_payload_is_reported(tmp_path):
    pcap, manifest = _evidence(tmp_path, packets=[
        (BASE, _packet(SRC, DST, 40000, 18100, 0x02)[:-1]),
    ])

    report = verify_attack_evidence(pcap, manifest)

    assert report["status"] == "BLOCKED"
    assert any("truncated" in issue.lower() for issue in report["issues"])


def test_capture_packet_and_time_bounds_are_enforced(tmp_path):
    packets = [
        (BASE + timedelta(seconds=i * 7), _packet(SRC, DST, 40000 + (i % 24), PORTS[i % 24], 0x02))
        for i in range(21)
    ]
    pcap, manifest = _evidence(tmp_path, packets=packets)

    report = verify_attack_evidence(pcap, manifest)

    assert report["status"] == "BLOCKED"
    assert any("120" in issue for issue in report["issues"])


def test_unexpected_allowed_port_tuple_is_out_of_scope(tmp_path):
    packets = [
        (BASE, _packet(SRC, DST, 49999, 18100, 0x02)),
    ]
    pcap, manifest = _evidence(tmp_path, packets=packets)

    report = verify_attack_evidence(pcap, manifest)

    assert report["status"] == "BLOCKED"
    assert any("out-of-scope" in issue.lower() for issue in report["issues"])


def test_invalid_capture_metadata_timestamp_is_reported(tmp_path):
    pcap, manifest = _evidence(tmp_path)
    metadata = tmp_path / "capture.json"
    metadata.write_text(json.dumps({
        "interface": "eth1", "snaplen": 96, "packet_limit": 5000,
        "duration_limit_seconds": 120, "start_utc": "not-a-timestamp",
        "end_utc": "2026-11-21T03:00:01Z",
    }), encoding="utf-8")

    report = verify_attack_evidence(pcap, manifest, capture_metadata_path=metadata)

    assert report["status"] == "BLOCKED"
    assert any("metadata" in issue.lower() for issue in report["issues"])


def test_eve_correlation_is_partial_when_events_are_missing(tmp_path):
    pcap, manifest = _evidence(tmp_path)
    eve = tmp_path / "eve.jsonl"
    eve.write_text(json.dumps({
        "timestamp": "2026-11-21T03:00:00.001Z",
        "event_type": "flow",
        "flow_id": 123,
        "proto": "TCP",
        "src_ip": SRC,
        "src_port": 40000,
        "dest_ip": DST,
        "dest_port": 18100,
    }) + "\n", encoding="utf-8")

    report = verify_attack_evidence(pcap, manifest, eve)

    assert report["status"] == "PARTIAL"
    assert report["eve"]["matched_records"] == 1
    assert report["eve"]["unmatched_attack_attempts"] == 23


def test_manifest_result_count_does_not_prove_capture(tmp_path):
    manifest = _manifest()
    manifest.update({"rst_refused_count": 24})
    pcap, manifest_path = _evidence(
        tmp_path,
        manifest=manifest,
        packets=[(BASE, _packet(SRC, DST, 49999, 18099, 0x02))],
    )

    report = verify_attack_evidence(pcap, manifest_path)

    assert report["status"] == "BLOCKED"
    assert report["attack"]["matched_attempts"] == 0


def test_packet_failure_cannot_be_downgraded_to_partial_by_eve(tmp_path):
    manifest = _manifest()
    pcap, manifest_path = _evidence(
        tmp_path,
        manifest=manifest,
        packets=[(BASE, _packet(SRC, DST, 49999, 18099, 0x02))],
    )
    eve = tmp_path / "eve.jsonl"
    eve.write_text(json.dumps({
        "timestamp": "2026-11-21T03:00:00Z",
        "event_type": "flow",
        "flow_id": 1,
        "proto": "TCP",
        "src_ip": SRC,
        "src_port": 49999,
        "dest_ip": DST,
        "dest_port": 18100,
    }) + "\n", encoding="utf-8")

    report = verify_attack_evidence(pcap, manifest_path, eve)

    assert report["packet_status"] == "BLOCKED"
    assert report["eve_status"] == "PARTIAL"
    assert report["status"] == "BLOCKED"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda m: m["attempts"][0].update({"source_port": 0}),
        lambda m: m["attempts"][0].update({"destination_port": 18199}),
        lambda m: m["attempts"][0].update({"result": "timeout_filtered"}),
        lambda m: m["attempts"][1].update({
            "source_port": m["attempts"][0]["source_port"],
            "destination_port": m["attempts"][0]["destination_port"],
        }),
        lambda m: m["attempts"][0].update({"timestamp_utc": "2026-11-21T03:49:00Z"}),
    ],
)
def test_manifest_attempt_identity_scope_time_and_result_are_validated(tmp_path, mutate):
    manifest = _manifest()
    mutate(manifest)
    pcap, manifest_path = _evidence(tmp_path, manifest=manifest)

    report = verify_attack_evidence(pcap, manifest_path)

    assert report["status"] == "BLOCKED"
    assert any("manifest" in issue.lower() for issue in report["issues"])


def test_eve_flow_and_event_hashes_are_reported_without_overstating(tmp_path):
    pcap, manifest = _evidence(tmp_path)
    eve = tmp_path / "eve.jsonl"
    eve.write_text("\n".join([
        json.dumps({
            "timestamp": "2026-11-21T03:00:00Z", "event_type": "flow", "flow_id": 123,
            "event_hash": "hash-1", "proto": "TCP", "src_ip": SRC, "src_port": 40000,
            "dest_ip": DST, "dest_port": 18100,
        }),
        json.dumps({
            "timestamp": "2026-11-21T03:00:00Z", "event_type": "flow", "flow_id": 999,
            "event_hash": "hash-unmatched", "proto": "TCP", "src_ip": SRC, "src_port": 49999,
            "dest_ip": DST, "dest_port": 18100,
        }),
    ]) + "\n", encoding="utf-8")

    report = verify_attack_evidence(pcap, manifest, eve)

    assert report["eve"]["flow_id_matches"] == 1
    assert report["eve"]["event_hashes_observed"] == 2
    assert report["eve"]["unmatched_records"] == 1
    assert report["eve_status"] == "PARTIAL"
