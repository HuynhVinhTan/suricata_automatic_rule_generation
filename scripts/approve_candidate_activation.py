"""Create a candidate-specific owner approval after trusted replay verification."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from netids.candidate_record import (
    expected_candidate_runtime_id, verify_candidate_record,
    verify_signed_replay_evidence,
)
from netids.candidate_replay import _validate_isolated_root
from netids.key_pins import require_pinned_role_keys
from netids.lifecycle_ed25519 import sha256_file
from scripts.approve_isolated_activation import build_candidate_owner_authorization


PROMPT = "AUTHORIZE CANDIDATE ISOLATED ACTIVATION ONE TIME AND ROLLBACK"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--replay-attestation", type=Path, required=True)
    parser.add_argument("--replay-public", type=Path, required=True)
    parser.add_argument("--owner-private", type=Path, required=True)
    parser.add_argument("--owner-public", type=Path, required=True)
    parser.add_argument("--runtime-id", required=True)
    parser.add_argument("--target-vm", required=True)
    parser.add_argument("--interface", required=True)
    parser.add_argument("--isolated-root", type=Path, required=True)
    parser.add_argument("--approver-identity", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output.exists() or args.output.is_symlink():
        parser.error("Approval file exists: never overwrite an approval")
    candidate = json.loads(args.candidate.read_text(encoding="utf-8"))
    replay = json.loads(args.replay_attestation.read_text(encoding="utf-8"))
    if not isinstance(candidate, dict) or not verify_candidate_record(candidate):
        parser.error("Candidate record is invalid")
    replay_public = args.replay_public.read_bytes()
    owner_public = args.owner_public.read_bytes()
    require_pinned_role_keys(replay_public, owner_public)
    if not verify_signed_replay_evidence(candidate, replay, replay_public):
        parser.error("Replay attestation is not independently verified for this candidate")
    print(f"Candidate {candidate['candidate_id']} / SID {candidate['sid']}")
    print(f"Run ID: {candidate['run_id']}")
    try:
        root = str(_validate_isolated_root(args.isolated_root))
    except ValueError as exc:
        parser.error(f"Unsafe isolated root: {exc}")
    expected_runtime = expected_candidate_runtime_id(
        candidate, target_vm=args.target_vm, interface=args.interface, isolated_root=root,
    )
    if args.runtime_id != expected_runtime:
        parser.error("Runtime ID does not match the independently derived candidate scope")
    expires_preview = datetime.now(timezone.utc) + timedelta(minutes=15)
    print(f"Canonical rule SHA: {candidate['rule_sha256']}")
    print(f"Full rule-file SHA: {candidate['source_rule_file_sha256']}")
    print(f"Metadata SHA: {candidate['source_metadata_sha256']}")
    print(f"Review SHA: {candidate['review_sha256']}")
    print(f"Model SHA: {candidate['model_sha256']}")
    print(f"Calibration SHA: {candidate['calibration_sha256']}")
    print(f"Decision manifest SHA: {candidate['decision_manifest_sha256']}")
    print(f"Baseline rules SHA: {candidate['baseline_rules_sha256']}")
    print(f"Runtime ID: {expected_runtime}")
    print(f"Target VM / interface: {args.target_vm} / {args.interface}")
    print(f"Isolated root: {root}")
    print(f"Approval expiration: {expires_preview.isoformat()}")
    print("Mandatory rollback: yes; maximum activation window: 300 seconds")
    print("No action is performed until explicit owner confirmation.")
    if input(f"Type exactly '{PROMPT}' to authorize signing: ").strip() != PROMPT:
        parser.error("Owner confirmation was not given")
    password = getpass.getpass("Owner encrypted signing key passphrase: ").encode()
    approval = build_candidate_owner_authorization(
        candidate, replay, replay_public_pem=replay_public,
        owner_private_pem=args.owner_private.read_bytes(), owner_private_password=password,
        owner_public_pem=owner_public, approver_identity=args.approver_identity,
        candidate_record_sha256=sha256_file(args.candidate), runtime_id=args.runtime_id,
        target_vm=args.target_vm, interface=args.interface, isolated_root=root,
        nonce=secrets.token_hex(16),
    )
    args.output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(approval, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    print(f"Candidate owner approval saved: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
