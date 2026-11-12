"""Local, explicit Ed25519 owner authorization for one isolated operation."""
from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from backend.replay_attestation_service import _load_private, _load_public, canonical_json, signed_payload


class OwnerApprovalError(ValueError):
    pass


_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_NONCE = re.compile(r"^[0-9a-f]{32,64}$")
_CONFIRMATION = "ACTIVATE_ONCE_THEN_ROLLBACK"


def _utc(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise OwnerApprovalError("Approval timestamps must be timezone-aware UTC")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _sign(record: dict, private_key: Path, password: bytes | None) -> str:
    payload = signed_payload(record, "isolated-owner-approval-v1")
    return base64.b64encode(_load_private(private_key, password).sign(payload)).decode("ascii")


def create_owner_approval(*, private_key: Path, candidate: dict, target_vm: str,
                          isolated_runtime_id: str, interface: str, operation: str,
                          approver_identity: str, replay_evidence_sha256: str,
                          approved_at: datetime, expires_at: datetime, nonce: str,
                          confirmation: str | None, password: bytes | None = None) -> tuple[dict, str]:
    if confirmation != _CONFIRMATION:
        raise OwnerApprovalError("explicit typed confirmation is required")
    if operation != "activate_once_then_rollback" or target_vm != "suricata-vm1" or interface != "lo":
        raise OwnerApprovalError("Owner scope is not the approved isolated operation")
    if not _HEX64.fullmatch(replay_evidence_sha256) or not _NONCE.fullmatch(nonce):
        raise OwnerApprovalError("Invalid evidence hash or nonce")
    if expires_at <= approved_at or expires_at - approved_at > timedelta(minutes=15):
        raise OwnerApprovalError("Owner approval must expire within 15 minutes")
    record = {
        "schema_version": "isolated_owner_approval_v1",
        "candidate_id": candidate["candidate_id"], "run_id": candidate["run_id"],
        "sid": candidate["sid"], "rule_sha256": candidate["rule_sha256"],
        "target_vm": target_vm, "isolated_runtime_id": isolated_runtime_id,
        "interface": interface, "operation": operation,
        "approver_identity": approver_identity, "approved_at": _utc(approved_at),
        "expires_at": _utc(expires_at), "nonce": nonce,
        "replay_evidence_sha256": replay_evidence_sha256,
        "production_excluded": True, "rule_action": "alert",
    }
    return record, _sign(record, private_key, password)


def verify_owner_approval(record: dict, signature: str, public_key: Path, *, now: datetime | None = None,
                          expected_candidate: dict | None = None, used_nonces: set[str] | None = None) -> bool:
    try:
        if record.get("schema_version") != "isolated_owner_approval_v1":
            return False
        if record.get("target_vm") != "suricata-vm1" or record.get("isolated_runtime_id") != "isolated-lifecycle-9103003":
            return False
        if record.get("interface") != "lo" or record.get("operation") != "activate_once_then_rollback":
            return False
        if record.get("production_excluded") is not True or record.get("rule_action") != "alert":
            return False
        if expected_candidate is not None:
            for key in ("candidate_id", "run_id", "sid", "rule_sha256"):
                if record.get(key) != expected_candidate.get(key):
                    return False
        if not _HEX64.fullmatch(record.get("replay_evidence_sha256", "")) or not _NONCE.fullmatch(record.get("nonce", "")):
            return False
        if used_nonces is not None and record["nonce"] in used_nonces:
            return False
        approved = datetime.fromisoformat(record["approved_at"].replace("Z", "+00:00"))
        expires = datetime.fromisoformat(record["expires_at"].replace("Z", "+00:00"))
        current = now or datetime.now(timezone.utc)
        if approved.tzinfo is None or expires <= approved or expires - approved > timedelta(minutes=15) or expires <= current:
            return False
        signature_bytes = base64.b64decode(signature, validate=True)
        _load_public(public_key).verify(signature_bytes, signed_payload(record, "isolated-owner-approval-v1"))
        if used_nonces is not None:
            used_nonces.add(record["nonce"])
        return True
    except (KeyError, OSError, ValueError, TypeError, UnicodeError, InvalidSignature):
        return False


def approval_sha256(record: dict) -> str:
    return hashlib.sha256(canonical_json(record)).hexdigest()
