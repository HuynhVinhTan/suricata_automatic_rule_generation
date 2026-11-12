"""Windows-local owner authorization: exact one-time isolated lab activation.

Runs interactively and signs only after validating a trusted VM1 replay
attestation. There is NO network listener, deployment, SSH call, or auto-approval.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from netids.key_pins import require_pinned_role_keys
from netids.lifecycle_ed25519 import (
    sha256_file,
    sign_record,
    verify_record,
    public_key_fingerprint,
)
from netids.trusted_replay import SID, RULE_SHA, MODEL_SHA, CAL_SHA, DECISION_SHA

PROMPT = "AUTHORIZE ISOLATED SID 9103003 ONE TIME AND ROLLBACK"
ISOLATED_ROOT = "/home/tanhv/suricata-rule-review/isolated-lifecycle-9103003"
RUNTIME_ID = "suricata-vm1:isolated-lifecycle-9103003:lo"


def build_owner_authorization(
    replay_record: dict, *, replay_public_pem: bytes, owner_private_pem: bytes,
    owner_private_password: bytes, owner_public_pem: bytes, approver_identity: str,
    candidate_id: str, run_id: str, nonce: str,
    now: datetime | None = None,
) -> dict:
    """Independently verify real replay proof before signing scoped approval."""
    if not verify_record(
        replay_record, replay_public_pem, domain="isolated-replay-v1"
    ):
        raise ValueError("Replay evidence signature is not trusted")
    if (
        replay_record.get("sid") != SID
        or replay_record.get("rule_sha256") != RULE_SHA
        or replay_record.get("model_sha256") != MODEL_SHA
        or replay_record.get("calibration_sha256") != CAL_SHA
        or replay_record.get("decision_manifest_sha256") != DECISION_SHA
        or replay_record.get("syntax_authenticated") is not True
        or replay_record.get("attack_replay_passed") is not True
        or replay_record.get("normal_replay_passed") is not True
        or replay_record.get("normal_false_positive_count") != 0
        or len(replay_record.get("cases", [])) != 6
        or replay_record.get("candidate_id") != candidate_id
        or replay_record.get("run_id") != run_id
    ):
        raise ValueError("Replay acceptance or candidate provenance mismatch")
    from netids.trusted_replay import EXPECTED_CASES
    cases = replay_record.get("cases")
    if not isinstance(cases, list) or len(cases) != len(EXPECTED_CASES):
        raise ValueError("Original six-holdout evidence is incomplete")
    encountered = set()
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("Malformed signed replay case")
        case_id = case.get("run_id")
        if case_id not in EXPECTED_CASES or case_id in encountered:
            raise ValueError("Unknown or repeated replay run")
        scenario, sha = EXPECTED_CASES[case_id]
        if case.get("scenario") != scenario or case.get("pcap_sha256") != sha:
            raise ValueError("Replay case provenance mismatch")
        alert_count = case.get("candidate_sid_alerts")
        if type(alert_count) is not int or (alert_count <= 0 if scenario == "attack" else alert_count != 0):
            raise ValueError("Attack/Normal replay acceptance failed")
        encountered.add(case_id)
    if encountered != set(EXPECTED_CASES):
        raise ValueError("Missing original replay cases")
    if not isinstance(approver_identity, str) or not approver_identity.strip():
        raise ValueError("Approver identity is required")
    if len(nonce) != 32 or any(x not in "0123456789abcdef" for x in nonce):
        raise ValueError("Invalid nonce")
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("UTC time required")
    try:
        replay_time = datetime.fromisoformat(
            replay_record["created_at"].replace("Z", "+00:00")
        )
    except (KeyError, AttributeError, ValueError) as exc:
        raise ValueError("Replay attestation lacks a trusted UTC timestamp") from exc
    if replay_time.tzinfo is None:
        raise ValueError("Replay attestation timestamp is naive")
    age = now.astimezone(timezone.utc) - replay_time.astimezone(timezone.utc)
    if age < timedelta(minutes=-1) or age > timedelta(hours=1):
        raise ValueError("Replay attestation is stale or from the future")
    approved = now.astimezone(timezone.utc)
    expires = approved + timedelta(minutes=15)
    replay_unsigned = json.dumps(
        replay_record, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode()
    record = {
        "schema_version": "isolated_owner_approval_v1",
        "candidate_id": candidate_id,
        "run_id": run_id,
        "sid": SID,
        "rule_sha256": RULE_SHA,
        "pcap_sha256": replay_record["pcap_sha256"],
        "model_sha256": MODEL_SHA,
        "calibration_sha256": CAL_SHA,
        "replay_evidence_sha256": hashlib.sha256(replay_unsigned).hexdigest(),
        "environment": "isolated-lab",
        "isolated_root": ISOLATED_ROOT,
        "target_vm": "suricata-vm1",
        "interface": "lo",
        "runtime_id": RUNTIME_ID,
        "operation": "activate",
        "rollback_required": True,
        "max_activation_seconds": 300,
        "approver_identity": approver_identity.strip(),
        "approved_at": approved.isoformat(),
        "expires_at": expires.isoformat(),
        "nonce": nonce,
    }
    signed = sign_record(
        record, owner_private_pem, owner_private_password,
        domain="isolated-owner-approval-v1",
    )
    if not verify_record(signed, owner_public_pem, domain="isolated-owner-approval-v1"):
        raise ValueError("Owner private key does not match pinned owner public key")
    if public_key_fingerprint(owner_public_pem) == public_key_fingerprint(replay_public_pem):
        raise ValueError("Owner and replay keys must be independent")
    return signed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--replay-attestation", type=Path, required=True)
    parser.add_argument("--replay-public", type=Path, required=True)
    parser.add_argument("--owner-private", type=Path, required=True)
    parser.add_argument("--owner-public", type=Path, required=True)
    parser.add_argument("--candidate-id", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--approver-identity", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output.is_symlink() or args.output.exists():
        parser.error("Approval file exists: never overwrite or replay an approval")
    replay_record = json.loads(args.replay_attestation.read_text(encoding="utf-8"))
    replay_public = args.replay_public.read_bytes()
    owner_public = args.owner_public.read_bytes()
    require_pinned_role_keys(replay_public, owner_public)
    if not verify_record(replay_record, replay_public, domain="isolated-replay-v1"):
        parser.error("Replay attestation is unsigned or not trusted")
    print("One-time OWNER authorization request")
    print(f"Candidate: {args.candidate_id}")
    print(f"Run: {args.run_id}")
    print(f"SID: {SID}; rule SHA256: {RULE_SHA}")
    print(f"VM1 isolated root: {ISOLATED_ROOT}")
    print(f"Runtime ID: {RUNTIME_ID}; interface: lo")
    print("Operation: activate alert-only candidate once; mandatory verified rollback")
    print("Excluded: production Suricata, Filebeat, EVE, firewall and privileges")
    print("Approval expires in 15 minutes. No action is performed by this CLI.")
    if input("Type exactly '" + PROMPT + "' to authorize signing: ").strip() != PROMPT:
        parser.error("Owner confirmation was not given")
    password = getpass.getpass("Owner encrypted signing key passphrase: ").encode()
    record = build_owner_authorization(
        replay_record,
        replay_public_pem=replay_public,
        owner_private_pem=args.owner_private.read_bytes(),
        owner_private_password=password,
        owner_public_pem=owner_public,
        approver_identity=args.approver_identity,
        candidate_id=args.candidate_id,
        run_id=args.run_id,
        nonce=secrets.token_hex(16),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(record, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        args.output.unlink(missing_ok=True)
        raise
    print(f"Owner-signed authorization saved: {args.output}")
    print("Transfer only the public key, signed authorization and verified evidence.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
