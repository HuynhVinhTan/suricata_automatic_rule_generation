"""Read-only validation and correlation for the private lab Attack capture."""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import struct


SOURCE_IP = "192.168.10.20"
TARGET_IP = "192.168.10.10"
ATTACK_PORTS = set(range(18100, 18124))


def _utc(value: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("timestamp is required")
    text = value.strip().replace("Z", "+00:00")
    result = datetime.fromisoformat(text)
    if result.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return result.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_pcap(path: Path) -> dict:
    if not path.is_file() or path.stat().st_size == 0:
        raise ValueError("PCAP is missing or empty")
    raw_packets = []
    with path.open("rb") as stream:
        header = stream.read(24)
        if len(header) != 24:
            raise ValueError("PCAP global header is truncated")
        magic = header[:4]
        formats = {
            b"\xd4\xc3\xb2\xa1": ("<", False),
            b"\xa1\xb2\xc3\xd4": (">", False),
            b"\x4d\x3c\xb2\xa1": ("<", True),
            b"\xa1\xb2\x3c\x4d": (">", True),
        }
        if magic not in formats:
            raise ValueError("unsupported PCAP magic")
        endian, nano = formats[magic]
        version_major, version_minor, _zone, _sigfigs, snaplen, linktype = struct.unpack(
            f"{endian}HHIIII", header[4:]
        )
        if (version_major, version_minor) != (2, 4):
            raise ValueError("unsupported PCAP version")
        if snaplen <= 0:
            raise ValueError("invalid PCAP snaplen")
        if linktype != 1:
            raise ValueError(f"unsupported link type: {linktype}")
        while True:
            record = stream.read(16)
            if not record:
                break
            if len(record) != 16:
                raise ValueError("PCAP record header is truncated")
            seconds, fraction, captured, original = struct.unpack(f"{endian}IIII", record)
            if captured > snaplen or captured > original:
                raise ValueError("invalid PCAP record length")
            payload = stream.read(captured)
            if len(payload) != captured:
                raise ValueError("PCAP record payload is truncated")
            timestamp = datetime.fromtimestamp(seconds, timezone.utc).replace(
                microsecond=fraction // 1000 if nano else fraction
            )
            raw_packets.append((timestamp, payload, captured, original))
    if not raw_packets:
        raise ValueError("PCAP contains no packets")
    packets = []
    for timestamp, payload, captured, original in raw_packets:
        if len(payload) < 14:
            raise ValueError("truncated Ethernet packet")
        ethertype = struct.unpack("!H", payload[12:14])[0]
        if ethertype != 0x0800:
            packets.append({"timestamp": timestamp, "ip": None, "captured": captured, "original": original})
            continue
        if len(payload) < 34:
            raise ValueError("truncated IPv4 packet")
        ihl = (payload[14] & 0x0F) * 4
        total_length = struct.unpack("!H", payload[16:18])[0]
        if ihl < 20 or len(payload) < 14 + ihl or total_length < ihl:
            raise ValueError("invalid IPv4 header")
        protocol = payload[23]
        src = str(ipaddress.ip_address(payload[26:30]))
        dst = str(ipaddress.ip_address(payload[30:34]))
        tcp = None
        if protocol == 6:
            if len(payload) < 14 + ihl + 20:
                raise ValueError("truncated TCP packet")
            offset = 14 + ihl
            src_port, dst_port = struct.unpack("!HH", payload[offset:offset + 4])
            flags = payload[offset + 13]
            tcp = {"src_port": src_port, "dst_port": dst_port, "flags": flags}
        packets.append({
            "timestamp": timestamp,
            "ip": {"src": src, "dst": dst, "protocol": protocol, "tcp": tcp},
            "captured": captured,
            "original": original,
        })
    return {
        "packet_count": len(packets),
        "snaplen": snaplen,
        "link_type": linktype,
        "first_packet_utc": _iso(packets[0]["timestamp"]),
        "last_packet_utc": _iso(packets[-1]["timestamp"]),
        "packets": packets,
    }


def _attempts(manifest: dict) -> tuple[list[dict], datetime, datetime]:
    started = _utc(manifest["started_at_utc"])
    ended = _utc(manifest["ended_at_utc"])
    if ended < started:
        raise ValueError("manifest window ends before it starts")
    attempts = manifest.get("attempts")
    if not isinstance(attempts, list) or len(attempts) != 24:
        raise ValueError("manifest must contain exactly 24 attempts")
    normalized = []
    for attempt in attempts:
        timestamp = _utc(attempt["timestamp_utc"])
        source_port = int(attempt["source_port"])
        destination_port = int(attempt["destination_port"])
        normalized.append({
            **attempt,
            "timestamp": timestamp,
            "source_port": source_port,
            "destination_port": destination_port,
        })
    return normalized, started, ended


def verify_attack_evidence(
    pcap_path: str | Path,
    manifest_path: str | Path,
    eve_path: str | Path | None = None,
    *,
    expected_sha256: str | None = None,
    capture_metadata_path: str | Path | None = None,
) -> dict:
    pcap_path, manifest_path = Path(pcap_path), Path(manifest_path)
    issues: list[str] = []
    report = {
        "status": "BLOCKED",
        "issues": issues,
        "pcap": {},
        "manifest": {},
        "attack": {
            "distinct_destination_ports": [],
            "outbound_syn_packets": 0,
            "matched_attempts": 0,
            "missing_attempts": [],
            "matched_rst_responses": 0,
            "missing_rst_ports": [],
            "duplicate_syn_packets": 0,
        },
    }
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        attempts, manifest_start, manifest_end = _attempts(manifest)
        report["manifest"] = {
            "run_id": manifest.get("run_id"),
            "started_at_utc": _iso(manifest_start),
            "ended_at_utc": _iso(manifest_end),
        }
        if manifest.get("scenario") != "ATTACK":
            issues.append("manifest scenario is not ATTACK")
        if manifest.get("source_ip") != SOURCE_IP or manifest.get("target_ip") != TARGET_IP:
            issues.append("manifest source/target IP is outside the lab scope")
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        issues.append(f"invalid manifest: {exc}")
        return report
    try:
        pcap = _parse_pcap(pcap_path)
        digest = _sha256(pcap_path)
        report["pcap"] = {key: value for key, value in pcap.items() if key != "packets"}
        report["pcap"]["sha256"] = digest
        if pcap["snaplen"] != 96:
            issues.append(f"PCAP snaplen is {pcap['snaplen']}, expected 96")
        if expected_sha256 and digest.lower() != expected_sha256.lower():
            issues.append("PCAP SHA256 mismatch")
    except (OSError, ValueError) as exc:
        issues.append(f"invalid PCAP: {exc}")
        return report

    capture_meta = {}
    if capture_metadata_path:
        try:
            capture_meta = json.loads(Path(capture_metadata_path).read_text(encoding="utf-8"))
            report["capture"] = capture_meta
            if capture_meta.get("interface") != "eth1":
                issues.append("capture metadata interface is not eth1")
            if capture_meta.get("snaplen") != 96:
                issues.append("capture metadata snaplen is not 96")
            if capture_meta.get("packet_limit") != 5000 or capture_meta.get("duration_limit_seconds") != 120:
                issues.append("capture metadata limits do not match the bounded workflow")
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            issues.append(f"invalid capture metadata: {exc}")

    packets = pcap["packets"]
    capture_start = datetime.fromisoformat(report["pcap"]["first_packet_utc"].replace("Z", "+00:00"))
    capture_end = datetime.fromisoformat(report["pcap"]["last_packet_utc"].replace("Z", "+00:00"))
    if capture_end < manifest_start or capture_start > manifest_end:
        issues.append("capture and generator time windows do not overlap")
    if capture_meta.get("start_utc") and _utc(capture_meta["start_utc"]) > manifest_start:
        issues.append("capture started after the generator")
    if capture_meta.get("end_utc") and _utc(capture_meta["end_utc"]) < manifest_end:
        issues.append("capture ended before the generator")

    outbound = []
    inbound_rst = []
    out_of_scope = []
    for packet in packets:
        ip = packet["ip"]
        if not ip or ip["protocol"] != 6 or not ip["tcp"]:
            out_of_scope.append(packet)
            continue
        tcp = ip["tcp"]
        if ip["src"] == SOURCE_IP and ip["dst"] == TARGET_IP and tcp["dst_port"] in ATTACK_PORTS:
            if tcp["flags"] & 0x02 and not tcp["flags"] & 0x10:
                outbound.append((packet["timestamp"], tcp["src_port"], tcp["dst_port"]))
            else:
                out_of_scope.append(packet)
        elif ip["src"] == TARGET_IP and ip["dst"] == SOURCE_IP and tcp["src_port"] in ATTACK_PORTS and tcp["flags"] & 0x04:
            inbound_rst.append((packet["timestamp"], tcp["src_port"], tcp["dst_port"]))
        else:
            out_of_scope.append(packet)
    if out_of_scope:
        issues.append(f"{len(out_of_scope)} out-of-scope or non-TCP packets found")

    matched = []
    missing = []
    duplicate_count = 0
    matched_rst = 0
    missing_rst = []
    for attempt in attempts:
        key = (attempt["source_port"], attempt["destination_port"])
        syns = [
            item for item in outbound
            if item[1:] == key and manifest_start <= item[0] <= manifest_end
        ]
        if len(syns) > 1:
            duplicate_count += len(syns) - 1
        if not syns:
            missing.append(attempt)
            continue
        matched.append(attempt)
        response = [
            item for item in inbound_rst
            if item[1:] == (attempt["destination_port"], attempt["source_port"])
            and any(syn[0] <= item[0] <= manifest_end for syn in syns)
        ]
        if response:
            matched_rst += 1
        else:
            missing_rst.append(attempt["destination_port"])
    observed_ports = sorted({item[2] for item in outbound})
    report["attack"] = {
        "distinct_destination_ports": observed_ports,
        "outbound_syn_packets": len(outbound),
        "matched_attempts": len(matched),
        "missing_attempts": [item["destination_port"] for item in missing],
        "matched_rst_responses": matched_rst,
        "missing_rst_ports": missing_rst,
        "duplicate_syn_packets": duplicate_count,
        "capture_drop_statistics": capture_meta.get("drop_statistics", "UNAVAILABLE"),
    }
    if len(observed_ports) != 24 or observed_ports != sorted(ATTACK_PORTS):
        issues.append("PCAP does not contain exactly the 24 allowlisted Attack destination ports")
    if missing:
        issues.append(f"{len(missing)} manifest SYN attempts were not matched by actual five-tuples")
    if missing_rst:
        issues.append(f"missing inbound RST responses for ports: {missing_rst}")
    if duplicate_count:
        issues.append(f"{duplicate_count} duplicate SYN/retransmission packets found")

    if eve_path:
        eve = {"records": 0, "matched_records": 0, "unmatched_records": 0, "unmatched_attack_attempts": 24, "status": "BLOCKED"}
        matched_eve_keys = set()
        try:
            for line_number, line in enumerate(Path(eve_path).read_text(encoding="utf-8").splitlines(), 1):
                if not line.strip():
                    continue
                event = json.loads(line)
                eve["records"] += 1
                if str(event.get("proto", "")).upper() != "TCP":
                    eve["unmatched_records"] += 1
                    continue
                key = (event.get("src_ip"), event.get("src_port"), event.get("dest_ip"), event.get("dest_port"))
                if key not in {(a["source_ip"] if "source_ip" in a else SOURCE_IP, a["source_port"], a["target_ip"], a["destination_port"]) for a in attempts}:
                    eve["unmatched_records"] += 1
                    continue
                try:
                    event_time = _utc(event["timestamp"])
                except (KeyError, ValueError):
                    eve["unmatched_records"] += 1
                    continue
                if manifest_start <= event_time <= manifest_end:
                    eve["matched_records"] += 1
                    matched_eve_keys.add((key, event_time.date()))
                else:
                    eve["unmatched_records"] += 1
        except (OSError, json.JSONDecodeError) as exc:
            issues.append(f"invalid EVE JSONL at line {line_number if 'line_number' in locals() else '?'}: {exc}")
        eve["unmatched_attack_attempts"] = max(0, len(matched) - len({key for key, _date in matched_eve_keys}))
        eve["status"] = "PASS" if eve["unmatched_attack_attempts"] == 0 and eve["unmatched_records"] == 0 else "PARTIAL"
        report["eve"] = eve
    else:
        report["eve"] = {"status": "NOT_PROVIDED", "matched_records": 0, "unmatched_attack_attempts": len(matched)}

    if not issues:
        report["status"] = "PARTIAL" if report["eve"]["status"] == "PARTIAL" else "PASS"
    elif report.get("eve", {}).get("status") == "PARTIAL" and len(matched) == 24:
        report["status"] = "PARTIAL"
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--eve", type=Path)
    parser.add_argument("--expected-sha256")
    parser.add_argument("--capture-metadata", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    result = verify_attack_evidence(
        args.pcap,
        args.manifest,
        args.eve,
        expected_sha256=args.expected_sha256,
        capture_metadata_path=args.capture_metadata,
    )
    output = json.dumps(result, indent=2, sort_keys=True)
    if args.report:
        args.report.write_text(output + "\n", encoding="utf-8")
    print(output)
    return 0 if result["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
