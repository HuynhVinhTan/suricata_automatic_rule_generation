"""LAB_DEMO_ONLY VM2-to-VM3 signed envelope and SQLite replay gate."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3

from netids.lifecycle_ed25519 import (
    public_key_fingerprint,
    sign_record,
    verify_record,
)


G3_DOMAIN = "lab-demo-vm2-vm3-v1"
_HEX = re.compile(r"^[0-9a-f]{64}$")
_RUN_ID = re.compile(r"^g3-[A-Za-z0-9][A-Za-z0-9_.:-]{7,127}$")
_EVENT_ID = re.compile(r"^g3-event-[A-Za-z0-9][A-Za-z0-9_.:-]{7,127}$")
_CAPTURE_ID = re.compile(r"^capture-\d{8}T\d{6}Z-[0-9a-f]{16}$")
_GENERATOR_ID = re.compile(
    r"^g[24]-(?:live-)?[a-z]+-\d{8}T\d{6}Z-[0-9a-f]{16}$"
)


class G3ReplayError(ValueError):
    """A malformed, untrusted, or already-consumed LAB_DEMO_ONLY envelope."""


def _canonical(value: Mapping) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _validate_payload(record: Mapping, *, allow_attestation: bool = False) -> dict:
    if not isinstance(record, Mapping):
        raise G3ReplayError("envelope is not an object")
    if not allow_attestation and any(str(key).startswith("attestation_") for key in record):
        raise G3ReplayError("attestation fields are signer-owned")
    payload = dict(record)
    if payload.get("schema_version") != "lab_demo_attestation_v1":
        raise G3ReplayError("unsupported LAB_DEMO_ONLY schema")
    if not isinstance(payload.get("run_id"), str) or not _RUN_ID.fullmatch(payload["run_id"]):
        raise G3ReplayError("invalid LAB_DEMO_ONLY run_id")
    if not isinstance(payload.get("event_id"), str) or not _EVENT_ID.fullmatch(payload["event_id"]):
        raise G3ReplayError("invalid LAB_DEMO_ONLY event_id")
    if isinstance(payload.get("sequence"), bool) or not isinstance(payload.get("sequence"), int):
        raise G3ReplayError("sequence must be an integer")
    if payload["sequence"] < 0:
        raise G3ReplayError("sequence must be non-negative")
    if not isinstance(payload.get("nonce"), str) or not _HEX.fullmatch(payload["nonce"]):
        raise G3ReplayError("invalid LAB_DEMO_ONLY nonce")
    if payload.get("source_vm") != "suricata-vm2":
        raise G3ReplayError("unexpected LAB_DEMO_ONLY source VM")
    if payload.get("target_vm") != "suricata-vm3":
        raise G3ReplayError("unexpected LAB_DEMO_ONLY target VM")
    for field in ("artifact_sha256", "source_pcap_sha256", "manifest_sha256"):
        if not isinstance(payload.get(field), str) or not _HEX.fullmatch(payload[field]):
            raise G3ReplayError(f"invalid {field}")
    manifest = payload.get("manifest")
    if not isinstance(manifest, dict):
        raise G3ReplayError("manifest metadata object is required")
    if manifest.get("review_only") is not True:
        raise G3ReplayError("LAB_DEMO_ONLY manifest must be review-only")
    if manifest.get("pcap_sha256") != payload["source_pcap_sha256"]:
        raise G3ReplayError("manifest PCAP hash does not match signed source PCAP hash")
    expected_manifest_sha256 = hashlib.sha256(_canonical(manifest)).hexdigest()
    if payload["manifest_sha256"] != expected_manifest_sha256:
        raise G3ReplayError("manifest SHA256 does not match signed manifest metadata")
    evidence = payload.get("evidence")
    if not isinstance(evidence, dict) or evidence.get("review_only") is not True:
        raise G3ReplayError("LAB_DEMO_ONLY evidence must be review-only")
    issued_at = payload.get("issued_at_utc")
    if not isinstance(issued_at, str):
        raise G3ReplayError("issued_at_utc is required")
    try:
        parsed = datetime.fromisoformat(issued_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise G3ReplayError("issued_at_utc must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise G3ReplayError("issued_at_utc must include a timezone")
    try:
        _canonical(payload)
    except (TypeError, ValueError, UnicodeError) as exc:
        raise G3ReplayError("evidence is not canonical JSON") from exc
    return payload


def _regular_file(path: Path, label: str) -> Path:
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise G3ReplayError(f"{label} must be a regular non-symlink file")
    return path


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_json_file(path: Path, label: str) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise G3ReplayError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise G3ReplayError(f"{label} must be a JSON object")
    return value


def _verified_timestamp(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise G3ReplayError(f"{label} timestamp is missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise G3ReplayError(f"{label} timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise G3ReplayError(f"{label} timestamp has no timezone")
    return value


def build_lab_demo_record_from_evidence(
    *,
    capture_id: str,
    generator_id: str,
    pcap: Path,
    native_manifest: Path,
    ready_marker: Path,
    generator_json: Path,
    expected_pcap_sha256: str,
    expected_generator_sha256: str,
    g3_run_id: str,
    event_id: str,
    sequence: int,
    nonce: str,
) -> dict:
    """Build a G3 record only from a verified sealed capture and generator.

    The native manifest and ready marker remain byte-oriented evidence.  The
    review-only manifest is a separate canonical object whose digest is bound
    into the signed record; the two digests are never substituted for one
    another.
    """
    if not _CAPTURE_ID.fullmatch(capture_id):
        raise G3ReplayError("invalid capture_id")
    if not _GENERATOR_ID.fullmatch(generator_id):
        raise G3ReplayError("invalid generator_id")
    if not _HEX.fullmatch(expected_pcap_sha256) or not _HEX.fullmatch(expected_generator_sha256):
        raise G3ReplayError("expected evidence digest is invalid")
    if not _RUN_ID.fullmatch(g3_run_id) or not _EVENT_ID.fullmatch(event_id):
        raise G3ReplayError("invalid G3 run or event ID")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0:
        raise G3ReplayError("sequence must be a non-negative integer")
    if not isinstance(nonce, str) or not _HEX.fullmatch(nonce):
        raise G3ReplayError("invalid nonce")

    pcap = _regular_file(pcap, "PCAP")
    native_manifest = _regular_file(native_manifest, "Native manifest")
    ready_marker = _regular_file(ready_marker, "Ready marker")
    generator_json = _regular_file(generator_json, "Generator evidence")
    expected_names = {
        f"{capture_id}.pcap": pcap,
        f"{capture_id}.manifest.json": native_manifest,
        f"{capture_id}.ready.json": ready_marker,
    }
    if any(path.name != name for name, path in expected_names.items()):
        raise G3ReplayError("native evidence filenames do not preserve capture identity")

    actual_pcap_sha256 = _file_sha256(pcap)
    raw_manifest_sha256 = _file_sha256(native_manifest)
    actual_generator_sha256 = _file_sha256(generator_json)
    if actual_pcap_sha256 != expected_pcap_sha256:
        raise G3ReplayError("PCAP digest mismatch")
    if actual_generator_sha256 != expected_generator_sha256:
        raise G3ReplayError("generator evidence digest mismatch")

    native = _read_json_file(native_manifest, "Native manifest")
    ready = _read_json_file(ready_marker, "Ready marker")
    generator = _read_json_file(generator_json, "Generator evidence")
    if native.get("run_id") != capture_id or ready.get("run_id") != capture_id:
        raise G3ReplayError("native evidence capture ID mismatch")
    if ready.get("pcap_sha256") != expected_pcap_sha256:
        raise G3ReplayError("ready marker PCAP digest mismatch")
    if ready.get("manifest_sha256") != raw_manifest_sha256:
        raise G3ReplayError("ready marker native manifest digest mismatch")
    if native.get("pcap_sha256") != expected_pcap_sha256:
        raise G3ReplayError("native manifest PCAP digest mismatch")
    if native.get("source_ipv4") != "192.168.10.20" or native.get("destination_ipv4") != "192.168.10.10":
        raise G3ReplayError("native capture identity mismatch")
    if generator.get("run_id") != generator_id:
        raise G3ReplayError("generator evidence ID mismatch")
    if generator.get("source_ip") != "192.168.10.20" or generator.get("target_ip") != "192.168.10.10":
        raise G3ReplayError("generator source identity mismatch")
    attempts = generator.get("attempts")
    if not isinstance(attempts, list) or generator.get("attempt_count") != len(attempts):
        raise G3ReplayError("generator attempt evidence is incomplete")
    capture_metadata = native.get("capture_metadata")
    if not isinstance(capture_metadata, dict):
        raise G3ReplayError("native capture metadata is missing")
    sealed_at = _verified_timestamp(capture_metadata.get("sealed_at"), "capture sealed")
    generator_started = _verified_timestamp(generator.get("started_at_utc"), "generator start")
    generator_ended = _verified_timestamp(generator.get("ended_at_utc"), "generator end")

    review_manifest = {
        "schema_version": "lab_demo_capture_manifest_v1",
        "review_only": True,
        "capture_id": capture_id,
        "generator_id": generator_id,
        "pcap_sha256": expected_pcap_sha256,
        "native_manifest_sha256": raw_manifest_sha256,
        "generator_sha256": expected_generator_sha256,
        "source_vm": "suricata-vm2",
        "target_vm": "suricata-vm3",
        "source_ipv4": native.get("source_ipv4"),
        "destination_ipv4": native.get("destination_ipv4"),
        "capture_sealed_at_utc": sealed_at,
        "generator_started_at_utc": generator_started,
        "generator_ended_at_utc": generator_ended,
        "packet_count": capture_metadata.get("packets"),
        "initial_syn": capture_metadata.get("initial_syn"),
        "attempt_count": generator.get("attempt_count"),
    }
    evidence = {
        "review_only": True,
        "pcap_filename": pcap.name,
        "native_manifest_filename": native_manifest.name,
        "ready_marker_filename": ready_marker.name,
        "generator_filename": generator_json.name,
        "native_manifest_sha256": raw_manifest_sha256,
        "ready_manifest_sha256": ready.get("manifest_sha256"),
        "generator_sha256": expected_generator_sha256,
        "capture_id": capture_id,
        "generator_id": generator_id,
        "source_identity": "suricata-vm2/192.168.10.20",
        "target_identity": "suricata-vm1/192.168.10.10",
        "timestamps": {
            "capture_sealed_at_utc": sealed_at,
            "generator_started_at_utc": generator_started,
            "generator_ended_at_utc": generator_ended,
        },
    }
    record = {
        "schema_version": "lab_demo_attestation_v1",
        "run_id": g3_run_id,
        "event_id": event_id,
        "sequence": sequence,
        "nonce": nonce,
        "source_vm": "suricata-vm2",
        "target_vm": "suricata-vm3",
        "artifact_sha256": expected_generator_sha256,
        "source_pcap_sha256": expected_pcap_sha256,
        "issued_at_utc": generator_ended,
        "manifest": review_manifest,
        "manifest_sha256": hashlib.sha256(_canonical(review_manifest)).hexdigest(),
        "evidence": evidence,
    }
    return _validate_payload(record)


def sign_lab_demo_record(record: Mapping, private_pem: bytes, password: bytes) -> dict:
    """Sign a VM2 LAB_DEMO_ONLY record; no private key leaves the caller."""
    payload = dict(record)
    payload.setdefault(
        "issued_at_utc",
        datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    )
    payload = _validate_payload(payload)
    return sign_record(payload, private_pem, password, domain=G3_DOMAIN)


def _reject_symlink_path(path: Path) -> None:
    path = Path(path)
    if path.is_symlink():
        raise G3ReplayError("SQLite replay path may not be a symlink")
    for parent in path.parents:
        if parent == Path(parent.anchor):
            break
        if parent.is_symlink():
            raise G3ReplayError("SQLite replay parent may not be a symlink")


def _ensure_schema(db: sqlite3.Connection) -> None:
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("PRAGMA journal_mode = DELETE")
    db.execute("PRAGMA synchronous = FULL")
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS verified_envelopes (
            nonce TEXT PRIMARY KEY,
            run_id TEXT NOT NULL UNIQUE,
            event_id TEXT NOT NULL UNIQUE,
            sequence INTEGER NOT NULL,
            envelope_sha256 TEXT NOT NULL UNIQUE,
            signer_fingerprint TEXT NOT NULL,
            artifact_sha256 TEXT NOT NULL,
            source_pcap_sha256 TEXT NOT NULL,
            manifest_sha256 TEXT NOT NULL,
            verified_at_utc TEXT NOT NULL
        )
        """
    )


def verify_and_record_lab_demo(
    envelope: Mapping,
    public_pem: bytes,
    *,
    pinned_fingerprint: str,
    sqlite_path: Path,
) -> dict:
    """Verify a pinned VM2 signature, then atomically consume its nonce once."""
    if not isinstance(pinned_fingerprint, str) or not _HEX.fullmatch(pinned_fingerprint):
        raise G3ReplayError("invalid pinned public-key fingerprint")
    try:
        actual_fingerprint = public_key_fingerprint(public_pem)
    except (TypeError, ValueError) as exc:
        raise G3ReplayError("invalid Ed25519 public key") from exc
    if actual_fingerprint != pinned_fingerprint:
        raise G3ReplayError("public key does not match pinned fingerprint")
    if not verify_record(envelope, public_pem, domain=G3_DOMAIN):
        raise G3ReplayError("Ed25519 signature verification failed")
    payload = _validate_payload(envelope, allow_attestation=True)
    envelope_sha256 = hashlib.sha256(_canonical(envelope)).hexdigest()

    db_path = Path(sqlite_path)
    _reject_symlink_path(db_path)
    db_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _reject_symlink_path(db_path)
    old_umask = os.umask(0o077)
    try:
        db = sqlite3.connect(db_path)
    finally:
        os.umask(old_umask)
    try:
        _ensure_schema(db)
        db.execute("BEGIN IMMEDIATE")
        try:
            db.execute(
                """
                INSERT INTO verified_envelopes
                (nonce, run_id, event_id, sequence, envelope_sha256,
                 signer_fingerprint, artifact_sha256, source_pcap_sha256,
                 manifest_sha256, verified_at_utc)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload["nonce"],
                    payload["run_id"],
                    payload["event_id"],
                    payload["sequence"],
                    envelope_sha256,
                    actual_fingerprint,
                    payload["artifact_sha256"],
                    payload["source_pcap_sha256"],
                    payload["manifest_sha256"],
                    datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                ),
            )
        except sqlite3.IntegrityError as exc:
            db.rollback()
            raise G3ReplayError("replay rejected by SQLite nonce ledger") from exc
        db.commit()
    finally:
        db.close()
    db_path.chmod(0o600)
    return {
        "schema_version": "lab_demo_verification_v1",
        "verified": True,
        "replay": False,
        "run_id": payload["run_id"],
        "event_id": payload["event_id"],
        "sequence": payload["sequence"],
        "nonce": payload["nonce"],
        "envelope_sha256": envelope_sha256,
        "signer_fingerprint": actual_fingerprint,
        "source_pcap_sha256": payload["source_pcap_sha256"],
        "manifest_sha256": payload["manifest_sha256"],
        "sqlite_path": str(db_path),
    }

