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

