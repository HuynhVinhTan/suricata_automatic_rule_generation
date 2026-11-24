"""Small synthetic fixtures used only by offline capture-process tests."""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import struct


def _ip(value):
    return bytes(int(part) for part in value.split("."))


def _packet(src, dst, src_port, dst_port, flags):
    tcp = struct.pack("!HHIIBBHHH", src_port, dst_port, 0, 0, 5 << 4, flags, 65535, 0, 0)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0, 64, 6, 0, _ip(src), _ip(dst))
    return b"\x00" * 12 + b"\x08\x00" + ip + tcp


def _write_pcap(path, packets):
    with path.open("wb") as stream:
        stream.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 96, 1))
        for timestamp, payload in packets:
            stream.write(struct.pack("<IIII", int(timestamp.timestamp()), timestamp.microsecond, len(payload), len(payload)))
            stream.write(payload)


def write_complete_attack_fixture(directory: Path) -> tuple[Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    # The fixture is created before foreground authentication and mocked
    # supervisor startup. Keep packet timestamps safely ahead of that setup so
    # strict metadata ordering checks test evidence, not scheduling jitter.
    base = datetime.now(timezone.utc) + timedelta(seconds=30)
    attempts = []
    packets = []
    for index, port in enumerate(range(18100, 18124)):
        timestamp = base + timedelta(milliseconds=index * 10)
        source_port = 40000 + index
        attempts.append({
            "timestamp_utc": timestamp.isoformat().replace("+00:00", "Z"),
            "source_port": source_port,
            "target_ip": "192.168.10.10",
            "destination_port": port,
            "result": "rst_refused",
        })
        packets.append((timestamp, _packet("192.168.10.20", "192.168.10.10", source_port, port, 0x02)))
        packets.append((timestamp + timedelta(milliseconds=1), _packet("192.168.10.10", "192.168.10.20", port, source_port, 0x04)))
    manifest = {
        "schema_version": "lab_slow_port_scan_v1",
        "scenario": "ATTACK",
        "run_id": "process-test",
        "source_ip": "192.168.10.20",
        "target_ip": "192.168.10.10",
        "started_at_utc": (base - timedelta(milliseconds=100)).isoformat().replace("+00:00", "Z"),
        "ended_at_utc": (base + timedelta(milliseconds=500)).isoformat().replace("+00:00", "Z"),
        "attempt_count": 24,
        "attempts": attempts,
    }
    pcap = directory / "fixture.pcap"
    manifest_path = directory / "fixture.json"
    _write_pcap(pcap, packets)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return pcap, manifest_path
