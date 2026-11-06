"""Explicit, fail-closed PCAP handoff: VM1 sealed bundles -> VM3 review-only worker.

This module does not capture live traffic, modify Suricata, train a model,
approve a rule or deploy anything. Nothing is transferred/processed without
the explicit --execute flag.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import socket
import struct
import subprocess
from datetime import datetime, timezone
from ipaddress import IPv4Address
from pathlib import Path

SCHEMA = "phase3_pcap_handoff_v0_1"
WORKER_SCHEMA = "pcap_ai_worker_v0_1"
MAX_PCAP_BYTES = 512 * 1024 * 1024
RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
SSH_USER = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
REMOTE_PATH = re.compile(r"^/[A-Za-z0-9_./-]+$")


class HandoffError(ValueError):
    """A handoff invariant is not met."""


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run_id(value: str) -> str:
    if not RUN_ID.fullmatch(value):
        raise HandoffError("Unsafe run ID")
    return value


def _hash(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def _file(path: Path, root: Path) -> Path:
    if path.is_symlink() or not path.is_file():
        raise HandoffError("Input must be a regular, non-symlink file")
    resolved = path.resolve(strict=True)
    try:
        resolved.relative_to(root.resolve(strict=True))
    except ValueError as exc:
        raise HandoffError("Input escapes the allowlisted root") from exc
    if path.stat().st_size > MAX_PCAP_BYTES:
        raise HandoffError("PCAP exceeds the 512 MiB handoff limit")
    return resolved


def _root(path: Path) -> Path:
    if path.is_symlink() or not path.is_dir():
        raise HandoffError("An existing, non-symlink directory is required")
    resolved = path.resolve(strict=True)
    if resolved == resolved.parent:
        raise HandoffError("Filesystem root is not an acceptable input root")
    return resolved


def _json_exclusive(path: Path, value: dict) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    path.chmod(0o600)


def _read_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError) as exc:
        raise HandoffError("Invalid JSON handoff document") from exc
    if not isinstance(data, dict):
        raise HandoffError("Handoff document must be an object")
    return data


def audit_pcap(path: Path, src: str, dst: str) -> dict:
    """Read-only classic Ethernet PCAP structural and SYN/GET-count check.

    Deliberately not a PCAP-NG, IP fragment, or TCP stream reassembly parser.
    Captured packets with pre-TX-offload checksums remain raw evidence.
    """
    source, destination = IPv4Address(src).packed, IPv4Address(dst).packed
    if source == destination:
        raise HandoffError("Source and destination must differ")
    packets = syn = gets = 0
    with path.open("rb") as stream:
        header = stream.read(24)
        if len(header) != 24:
            raise HandoffError("PCAP global header is incomplete")
        byte_order = {
            b"\xd4\xc3\xb2\xa1": "<",
            b"\xa1\xb2\xc3\xd4": ">",
            b"\x4d\x3c\xb2\xa1": "<",
            b"\xa1\xb2\x3c\x4d": ">",
        }.get(header[:4])
        if byte_order is None:
            raise HandoffError("Only classic PCAP is supported")
        snaplen = struct.unpack_from(byte_order + "I", header, 16)[0]
        linktype = struct.unpack_from(byte_order + "I", header, 20)[0]
        if linktype != 1 or snaplen < 65535:
            raise HandoffError("Expected full-snaplen Ethernet PCAP")
        while True:
            record = stream.read(16)
            if not record:
                break
            if len(record) != 16:
                raise HandoffError("Incomplete PCAP record header")
            _, _, included, original = struct.unpack(byte_order + "IIII", record)
            if included != original or included > snaplen or included < 14:
                raise HandoffError("Truncated or invalid PCAP packet record")
            frame = stream.read(included)
            if len(frame) != included:
                raise HandoffError("Incomplete PCAP record payload")
            packets += 1
            kind = struct.unpack_from("!H", frame, 12)[0]
            offset = 14
            while kind in (0x8100, 0x88A8):
                if offset + 4 > len(frame):
                    raise HandoffError("Malformed VLAN header")
                kind = struct.unpack_from("!H", frame, offset + 2)[0]
                offset += 4
            if kind != 0x0800:
                continue
            ip = frame[offset:]
            if len(ip) < 20 or ip[0] >> 4 != 4:
                raise HandoffError("Malformed IPv4 header")
            ihl = (ip[0] & 15) * 4
            length = struct.unpack_from("!H", ip, 2)[0]
            flags_fragment = struct.unpack_from("!H", ip, 6)[0]
            if ihl < 20 or length < ihl or length > len(ip):
                raise HandoffError("Malformed/truncated IPv4 packet")
            if ip[9] != 6 or flags_fragment & 0x3fff:
                continue
            if ip[12:16] != source or ip[16:20] != destination:
                continue
            tcp = ip[ihl:length]
            if len(tcp) < 20:
                raise HandoffError("Malformed TCP packet")
            tcp_hlen = (tcp[12] >> 4) * 4
            if tcp_hlen < 20 or tcp_hlen > len(tcp):
                raise HandoffError("Malformed TCP header length")
            if tcp[13] & 0x12 == 0x02:
                syn += 1
            if tcp[tcp_hlen:].startswith(b"GET "):
                gets += 1
    if packets == 0 or syn == 0:
        raise HandoffError("PCAP contains no packets or expected initial SYN")
    return {"packets": packets, "initial_syn": syn, "http_get_starts": gets, "snaplen": snaplen}


def _bundle_paths(root: Path, run_id: str) -> tuple[Path, Path, Path]:
    return tuple(root / f"{run_id}{suffix}" for suffix in (
        ".pcap", ".manifest.json", ".ready.json",
    ))


def bundle(
    *, pcap: Path, input_root: Path, outbox: Path, run_id: str,
    src: str, dst: str, expected_sha256: str,
    expected_syn: int, expected_get: int | None = None,
    capture_kind: str = "raw",
) -> dict:
    run_id = _run_id(run_id)
    inroot, outroot = _root(input_root), _root(outbox)
    source = _file(pcap, inroot)
    if not SHA256.fullmatch(expected_sha256):
        raise HandoffError("Expected SHA256 must be a verified 64-digit digest")
    if type(expected_syn) is not int or expected_syn < 1:
        raise HandoffError("Expected SYN count must be positive")
    if expected_get is not None and (type(expected_get) is not int or expected_get < 0):
        raise HandoffError("Expected GET count must be nonnegative")
    if capture_kind not in {"raw", "checksum-normalized"}:
        raise HandoffError("Unrecognized capture kind")
    audit = audit_pcap(source, src, dst)
    if audit["initial_syn"] != expected_syn or (
        expected_get is not None and audit["http_get_starts"] != expected_get
    ):
        raise HandoffError("PCAP SYN/GET count does not match the scenario gate")
    digest = _hash(source)
    if digest != expected_sha256.lower():
        raise HandoffError("Original PCAP SHA256 mismatch")
    target_dir = outroot / run_id
    target_dir.mkdir(mode=0o700, exist_ok=False)
    pcap_out, manifest_out, ready_out = _bundle_paths(target_dir, run_id)
    # Never finalize an unsuccessful/incomplete copy with a ready marker.
    with source.open("rb") as inp, pcap_out.open("xb") as dst_file:
        shutil.copyfileobj(inp, dst_file, length=1024 * 1024)
        dst_file.flush()
        os.fsync(dst_file.fileno())
    pcap_out.chmod(0o600)
    if _hash(pcap_out) != digest or _hash(source) != digest:
        raise HandoffError("Source or copied PCAP changed during sealing")
    manifest = {
        "schema_version": WORKER_SCHEMA,
        "pcap_sha256": digest,
        "source_ipv4": str(IPv4Address(src)),
        "destination_ipv4": str(IPv4Address(dst)),
        "run_id": run_id,
        "capture_metadata": {
            **audit,
            "capture_kind": capture_kind,
            "sealed_at": _utc(),
        },
    }
    _json_exclusive(manifest_out, manifest)
    ready = {
        "schema_version": SCHEMA,
        "run_id": run_id,
        "pcap_sha256": digest,
        "manifest_sha256": _hash(manifest_out),
    }
    _json_exclusive(ready_out, ready)
    return {"status": "sealed", "run_id": run_id, "pcap_sha256": digest, **audit}


def verified_bundle(root: Path, run_id: str) -> tuple[Path, Path, Path, dict]:
    run_id = _run_id(run_id)
    root = _root(root)
    pcap, manifest, ready = _bundle_paths(root, run_id)
    for path in (pcap, manifest, ready):
        _file(path, root)
    seal = _read_json(ready)
    doc = _read_json(manifest)
    if (seal.get("schema_version") != SCHEMA
        or seal.get("run_id") != run_id
        or doc.get("schema_version") != WORKER_SCHEMA
        or doc.get("run_id") != run_id
        or seal.get("pcap_sha256") != doc.get("pcap_sha256")
        or doc.get("pcap_sha256") != _hash(pcap)
        or seal.get("manifest_sha256") != _hash(manifest)):
        raise HandoffError("Bundle identity or checksum mismatch")
    src = str(IPv4Address(doc.get("source_ipv4")))
    dst = str(IPv4Address(doc.get("destination_ipv4")))
    audit = audit_pcap(pcap, src, dst)
    meta = doc.get("capture_metadata")
    if not isinstance(meta, dict) or any(meta.get(k) != audit[k] for k in audit):
        raise HandoffError("Manifest PCAP audit metadata mismatch")
    return pcap, manifest, ready, doc


def _ssh_options() -> list[str]:
    return [
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "ConnectTimeout=10",
        "-o", "ServerAliveInterval=10",
        "-o", "ServerAliveCountMax=2",
    ]


def send(
    *, outbox: Path, run_id: str, remote_user: str, remote_host: str,
    remote_inbox: str, execute: bool,
) -> dict:
    run_id = _run_id(run_id)
    root = _root(outbox)
    pcap, manifest, ready, doc = verified_bundle(root / run_id, run_id)
    if not SSH_USER.fullmatch(remote_user):
        raise HandoffError("Invalid SSH user")
    # Hosts are pinned lab IPv4 addresses, never arbitrary SSH aliases.
    host = str(IPv4Address(remote_host))
    if host != "192.168.10.30":
        raise HandoffError("Only designated lab VM3 192.168.10.30 is allowed")
    if not REMOTE_PATH.fullmatch(remote_inbox) or ".." in remote_inbox.split("/"):
        raise HandoffError("Remote inbox must be a safe absolute path")
    target = f"{remote_user}@{host}"
    receipt = root / run_id / f"{run_id}.sent.json"
    if receipt.exists() or receipt.is_symlink():
        old = _read_json(_file(receipt, root / run_id))
        if (old.get("status") != "sent"
            or old.get("run_id") != run_id
            or old.get("ready_sha256") != _hash(ready)
            or old.get("remote") != target
            or old.get("remote_inbox") != remote_inbox):
            raise HandoffError("Existing transfer receipt does not match")
        return {"status": "already_sent", "run_id": run_id, "remote": target}
    remote = [f"{remote_inbox}/{run_id}{suffix}" for suffix in (
        ".pcap", ".manifest.json", ".ready.json",
    )]
    staged = [name + ".partial" for name in remote]
    if not execute:
        return {"status": "validated_dry_run", "run_id": run_id, "remote": target}
    preflight = [
        "set -eu",
        f"test -d {shlex.quote(remote_inbox)}",
        f"test -w {shlex.quote(remote_inbox)}",
    ] + [f"test ! -e {shlex.quote(path)}" for path in remote + staged]
    subprocess.run(["ssh", *_ssh_options(), target, "; ".join(preflight)],
                   check=True, timeout=45)
    for local, partial in zip((pcap, manifest, ready), staged):
        subprocess.run(
            ["scp", "-B", *_ssh_options(), str(local), f"{target}:{partial}"],
            check=True, timeout=900,
        )
    hashes = (doc["pcap_sha256"], _hash(manifest), _hash(ready))
    final = ["set -eu"]
    for partial, sha in zip(staged, hashes):
        quoted = shlex.quote(partial)
        final.append(
            f"test \"$(sha256sum {quoted} | cut -d ' ' -f 1)\" = {sha}"
        )
    # Hardlink promotion never overwrites existing files; publish ready LAST.
    for partial, path in zip(staged, remote):
        final.append(f"ln -T -- {shlex.quote(partial)} {shlex.quote(path)}")
    final.extend(f"rm -- {shlex.quote(partial)}" for partial in staged)
    subprocess.run(["ssh", *_ssh_options(), target, "; ".join(final)],
                   check=True, timeout=90)
    # A local acknowledgment; no existing artifact is overwritten.
    _json_exclusive(receipt, {
        "status": "sent", "run_id": run_id,
        "ready_sha256": _hash(ready),
        "remote": target, "remote_inbox": remote_inbox, "sent_at": _utc(),
    })
    return {"status": "transferred", "run_id": run_id, "remote": target}


def consume(
    *, input_root: Path, private_root: Path, run_id: str,
    execute: bool, elasticsearch_url: str | None = None,
) -> dict:
    run_id = _run_id(run_id)
    root = _root(input_root)
    private = _root(private_root)
    pcap, manifest, _, document = verified_bundle(root, run_id)
    receipt = root / f"{run_id}.done.json"
    if receipt.exists() or receipt.is_symlink():
        done = _read_json(_file(receipt, root))
        summary_path = private / "lab-runs" / run_id / "worker_summary.json"
        summary = _read_json(_file(summary_path, private))
        if (done.get("run_id") != run_id
                or done.get("pcap_sha256") != document["pcap_sha256"]
                or done.get("status") != "succeeded"
                or done.get("summary_sha256") != _hash(summary_path)
                or summary.get("status") != "succeeded"
                or summary.get("pcap_sha256") != document["pcap_sha256"]):
            raise HandoffError("Existing receipt or worker summary does not match input")
        return {"status": "already_processed", "run_id": run_id}
    if not execute:
        return {"status": "validated_dry_run", "run_id": run_id,
                "pcap_sha256": document["pcap_sha256"]}
    # Import the worker only on VM3; VM1 requires stdlib only.
    from backend import worker
    summary = worker.run_worker(
        pcap=pcap,
        input_root=root,
        src=document["source_ipv4"],
        dst=document["destination_ipv4"],
        private_root=private,
        run_id=run_id,
        manifest_path=manifest,
    )
    if elasticsearch_url:
        worker.write_elasticsearch_summary(summary, elasticsearch_url)
    _json_exclusive(receipt, {
        "run_id": run_id,
        "pcap_sha256": document["pcap_sha256"],
        "summary_sha256": _hash(_file(private / "lab-runs" / run_id / "worker_summary.json", private)),
        "status": "succeeded",
        "completed_at": _utc(),
    })
    return {"status": "processed", "run_id": run_id,
            "review_status": summary["review_status"]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    seal = sub.add_parser("bundle")
    seal.add_argument("--pcap", type=Path, required=True)
    seal.add_argument("--input-root", type=Path, required=True)
    seal.add_argument("--outbox", type=Path, required=True)
    seal.add_argument("--run-id", required=True)
    seal.add_argument("--src", required=True)
    seal.add_argument("--dst", required=True)
    seal.add_argument("--expected-sha256", required=True)
    seal.add_argument("--expected-syn", type=int, required=True)
    seal.add_argument("--expected-get", type=int)
    seal.add_argument("--capture-kind", choices=("raw", "checksum-normalized"), default="raw")
    transfer = sub.add_parser("send")
    transfer.add_argument("--outbox", type=Path, required=True)
    transfer.add_argument("--run-id")
    transfer.add_argument("--all-ready", action="store_true")
    transfer.add_argument("--remote-user", required=True)
    transfer.add_argument("--remote-host", required=True)
    transfer.add_argument("--remote-inbox", required=True)
    transfer.add_argument("--execute", action="store_true")
    receiver = sub.add_parser("consume")
    receiver.add_argument("--input-root", type=Path, required=True)
    receiver.add_argument("--private-root", type=Path, required=True)
    receiver.add_argument("--run-id")
    receiver.add_argument("--all-ready", action="store_true")
    receiver.add_argument("--elasticsearch-url")
    receiver.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "bundle":
            result = bundle(
                pcap=args.pcap, input_root=args.input_root, outbox=args.outbox,
                run_id=args.run_id, src=args.src, dst=args.dst,
                expected_sha256=args.expected_sha256,
                expected_syn=args.expected_syn, expected_get=args.expected_get,
                capture_kind=args.capture_kind,
            )
        elif args.command == "send":
            if args.all_ready == bool(args.run_id):
                raise HandoffError("Select exactly one of --run-id or --all-ready")
            outbox = _root(args.outbox)
            run_ids = (
                [args.run_id] if args.run_id else
                sorted(path.name for path in outbox.iterdir()
                       if path.is_dir() and
                       (path / f"{path.name}.ready.json").exists())
            )
            if len(run_ids) > 10:
                raise HandoffError("Limit each send batch to 10 sealed bundles")
            result = [
                send(
                    outbox=outbox, run_id=rid,
                    remote_user=args.remote_user, remote_host=args.remote_host,
                    remote_inbox=args.remote_inbox, execute=args.execute,
                ) for rid in run_ids
            ]
        else:
            if args.all_ready == bool(args.run_id):
                raise HandoffError("Select exactly one of --run-id or --all-ready")
            root = _root(args.input_root)
            run_ids = (
                [args.run_id] if args.run_id else
                sorted(path.name[:-len(".ready.json")]
                       for path in root.glob("*.ready.json"))
            )
            if len(run_ids) > 10:
                raise HandoffError("Limit each batch to 10 ready bundles")
            result = [
                consume(
                    input_root=root, private_root=args.private_root,
                    run_id=rid, execute=args.execute,
                    elasticsearch_url=args.elasticsearch_url,
                ) for rid in run_ids
            ]
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception as exc:  # Fail closed without printing private paths or exception text.
        print(json.dumps({
            "status": "failed", "error_type": type(exc).__name__,
        }))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
