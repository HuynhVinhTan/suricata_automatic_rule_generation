"""Reproducible, read-only-by-default VM1 TX checksum normalization for PCAPs.

A checksum-normalized copy is DERIVED data, never a replacement for the raw
capture. Only invalid outbound TCP checksums are changed. No NIC, Suricata,
Filebeat, Elasticsearch, AI model or threshold settings are touched.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
from datetime import datetime, timezone
from ipaddress import IPv4Address
from pathlib import Path

MAX_SIZE = 512 * 1024 * 1024
MAGIC = {
    b"\xd4\xc3\xb2\xa1": "<",
    b"\xa1\xb2\xc3\xd4": ">",
    b"\x4d\x3c\xb2\xa1": "<",
    b"\xa1\xb2\x3c\x4d": ">",
}


class PCAPError(ValueError):
    """PCAP is not suitable for auditable checksum normalization."""


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def checksum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\0"
    count = len(data) // 2
    total = sum(struct.unpack(f"!{count}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def inspect_and_derive(
    raw: bytes, source_ipv4: str, destination_ipv4: str,
    *, allow_repair: bool = True,
) -> tuple[bytes, dict]:
    if len(raw) < 24 or raw[:4] not in MAGIC:
        raise PCAPError("Unsupported classic PCAP format")
    endian = MAGIC[raw[:4]]
    snaplen = struct.unpack_from(endian + "I", raw, 16)[0]
    linktype = struct.unpack_from(endian + "I", raw, 20)[0]
    if linktype != 1 or snaplen < 65535:
        raise PCAPError("Expected full-snaplen Ethernet PCAP")
    client = IPv4Address(source_ipv4).packed
    server = IPv4Address(destination_ipv4).packed
    if client == server:
        raise PCAPError("Source and destination must differ")
    result = {
        "snaplen": snaplen,
        "packets": 0,
        "initial_syn": 0,
        "http_get_starts": 0,
        "inbound_checked": 0,
        "outbound_checked": 0,
        "inbound_bad": 0,
        "outbound_bad_before": 0,
        "outbound_repaired": 0,
        "bad_after": 0,
        "truncated_records": 0,
    }
    out = bytearray(raw)
    pos = 24
    while pos < len(out):
        if pos + 16 > len(out):
            raise PCAPError("Incomplete record header")
        _, _, caplen, origlen = struct.unpack_from(endian + "IIII", out, pos)
        start, end = pos + 16, pos + 16 + caplen
        if caplen != origlen or caplen < 14 or caplen > snaplen or end > len(out):
            raise PCAPError("Truncated or malformed PCAP record")
        result["packets"] += 1
        kind = struct.unpack_from("!H", out, start + 12)[0]
        ip_pos = start + 14
        while kind in (0x8100, 0x88A8):
            if ip_pos + 4 > end:
                raise PCAPError("Malformed VLAN header")
            kind = struct.unpack_from("!H", out, ip_pos + 2)[0]
            ip_pos += 4
        if kind != 0x0800 or ip_pos + 20 > end:
            raise PCAPError("Unexpected Ethernet frame in TCP capture")
        ihl = (out[ip_pos] & 15) * 4
        version = out[ip_pos] >> 4
        total_length = struct.unpack_from("!H", out, ip_pos + 2)[0]
        frag = struct.unpack_from("!H", out, ip_pos + 6)[0]
        if (version != 4 or ihl < 20 or out[ip_pos + 9] != 6
            or frag & 0x3FFF or total_length < ihl + 20
            or ip_pos + ihl > end or ip_pos + total_length > end):
            raise PCAPError("Unsupported/truncated IPv4 TCP packet")
        source = bytes(out[ip_pos + 12:ip_pos + 16])
        target = bytes(out[ip_pos + 16:ip_pos + 20])
        if source == client and target == server:
            direction = "inbound"
            result["inbound_checked"] += 1
        elif source == server and target == client:
            direction = "outbound"
            result["outbound_checked"] += 1
        else:
            raise PCAPError("Unexpected IPv4 address in isolated PCAP")
        tcp_pos = ip_pos + ihl
        tcp_len = total_length - ihl
        tcp_hlen = (out[tcp_pos + 12] >> 4) * 4
        if tcp_hlen < 20 or tcp_hlen > tcp_len:
            raise PCAPError("Malformed TCP header")
        if direction == "inbound":
            if out[tcp_pos + 13] & 0x12 == 0x02:
                result["initial_syn"] += 1
            if out[tcp_pos + tcp_hlen:tcp_pos + tcp_len].startswith(b"GET "):
                result["http_get_starts"] += 1
        pseudo = source + target + b"\0\x06" + struct.pack("!H", tcp_len)
        segment = bytes(out[tcp_pos:tcp_pos + tcp_len])
        if checksum(pseudo + segment) != 0:
            if direction == "inbound":
                result["inbound_bad"] += 1
                raise PCAPError("Invalid inbound TCP checksum; refusing repair")
            result["outbound_bad_before"] += 1
            if allow_repair:
                fixed = bytearray(segment)
                fixed[16:18] = b"\0\0"
                out[tcp_pos + 16:tcp_pos + 18] = struct.pack(
                    "!H", checksum(pseudo + fixed)
                )
                result["outbound_repaired"] += 1
        if checksum(pseudo + bytes(out[tcp_pos:tcp_pos + tcp_len])) != 0:
            result["bad_after"] += 1
        pos = end
    if not result["packets"] or not result["initial_syn"]:
        raise PCAPError("Empty capture or missing initial SYN")
    return bytes(out), result


def normalize(
    *, pcap: Path, output: Path, expected_sha256: str,
    source_ipv4: str, destination_ipv4: str,
    expected_syn: int, expected_get: int,
    expected_bad_outbound: int | None, execute: bool,
) -> dict:
    if pcap.is_symlink() or not pcap.is_file():
        raise PCAPError("Source must be a regular, non-symlink PCAP")
    if pcap.stat().st_size > MAX_SIZE:
        raise PCAPError("PCAP exceeds 512 MiB limit")
    original = pcap.read_bytes()
    if (len(expected_sha256) != 64
        or any(c not in "0123456789abcdefABCDEF" for c in expected_sha256)
        or digest(original) != expected_sha256.lower()):
        raise PCAPError("Original source SHA256 mismatch")
    derived, stats = inspect_and_derive(
        original, source_ipv4, destination_ipv4
    )
    if (stats["initial_syn"] != expected_syn
        or stats["http_get_starts"] != expected_get):
        raise PCAPError("Scenario SYN/GET count mismatch")
    if expected_bad_outbound is not None and (
        stats["outbound_bad_before"] != expected_bad_outbound
    ):
        raise PCAPError("Unexpected outbound checksum repair count")
    # Verify the recomputed copy independently, WITHOUT allowing another repair.
    check, verified = inspect_and_derive(
        derived, source_ipv4, destination_ipv4, allow_repair=False
    )
    if check != derived or verified["bad_after"] != 0:
        raise PCAPError("Derived copy has invalid TCP checksums")
    if output.is_symlink() or output.exists():
        raise PCAPError("Output exists; refusing to overwrite")
    if output.parent.resolve(strict=True) != pcap.parent.resolve(strict=True):
        raise PCAPError("Output must be beside the original PCAP")
    if (not output.name.endswith("-checksum-normalized.pcap")
        or output.resolve() == pcap.resolve()):
        raise PCAPError("Output must clearly identify the derived copy")
    provenance = output.with_suffix(output.suffix + ".provenance.json")
    if provenance.exists() or provenance.is_symlink():
        raise PCAPError("Provenance record already exists")
    report = {
        "schema_version": "pcap_checksum_normalization_v0_1",
        "source_sha256": digest(original),
        "derived_sha256": digest(derived),
        "source_ipv4": str(IPv4Address(source_ipv4)),
        "destination_ipv4": str(IPv4Address(destination_ipv4)),
        "changes": "ONLY_INVALID_OUTBOUND_TCP_CHECKSUM_FIELDS",
        "capture_kind": "checksum-normalized",
        **stats,
        "status": "dry_run" if not execute else "succeeded",
    }
    if not execute:
        return report
    if expected_bad_outbound is None:
        raise PCAPError("--expected-bad-outbound required to write a derived copy")
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(derived)
        stream.flush()
        os.fsync(stream.fileno())
    if digest(output.read_bytes()) != report["derived_sha256"]:
        raise PCAPError("Derived file hash mismatch after write")
    if digest(pcap.read_bytes()) != report["source_sha256"]:
        raise PCAPError("Original source changed during normalization")
    report["created_at_utc"] = datetime.now(timezone.utc).isoformat()
    with provenance.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write("\n")
    provenance.chmod(0o600)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--src", required=True)
    parser.add_argument("--dst", required=True)
    parser.add_argument("--expected-syn", type=int, required=True)
    parser.add_argument("--expected-get", type=int, required=True)
    parser.add_argument("--expected-bad-outbound", type=int)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = normalize(
            pcap=args.pcap, output=args.output,
            expected_sha256=args.expected_sha256,
            source_ipv4=args.src, destination_ipv4=args.dst,
            expected_syn=args.expected_syn,
            expected_get=args.expected_get,
            expected_bad_outbound=args.expected_bad_outbound,
            execute=args.execute,
        )
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({"status": "failed", "error_type": type(exc).__name__}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
