#!/usr/bin/env python3
"""Create separate owner authorization for frozen SID9103005 G5 runtime."""

import argparse
import getpass
import json
import os
import secrets
from pathlib import Path

from netids.g5_frozen_candidate import build_frozen_owner_authorization, verify_frozen_candidate
from netids.lifecycle_ed25519 import public_key_fingerprint


PROMPT = "AUTHORIZE FROZEN SID9103005 ISOLATED ACTIVATION ONE TIME AND ROLLBACK"


def _write_exclusive(path, value):
    if path.exists() or path.is_symlink():
        raise ValueError("authorization output exists; never overwrite")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--replay-attestation", type=Path, required=True)
    parser.add_argument("--replay-public", type=Path, required=True)
    parser.add_argument("--owner-private", type=Path, required=True)
    parser.add_argument("--owner-public", type=Path, required=True)
    parser.add_argument("--runtime-public", type=Path, required=True)
    parser.add_argument("--isolated-root", required=True)
    parser.add_argument("--runtime-id", required=True)
    parser.add_argument("--target-vm", required=True)
    parser.add_argument("--interface", required=True)
    parser.add_argument("--approver-identity", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output.exists() or args.output.is_symlink():
        parser.error("authorization exists; never overwrite")
    candidate = json.loads(args.candidate.read_text(encoding="utf-8"))
    replay = json.loads(args.replay_attestation.read_text(encoding="utf-8"))
    replay_public = args.replay_public.read_bytes()
    owner_public = args.owner_public.read_bytes()
    try:
        verify_frozen_candidate(candidate, candidate.get("baseline_comparison"))
        print(f"Candidate ID: {candidate['candidate_id']}")
        print(f"SID: {candidate['sid']}; rule file SHA256: {candidate['rule_file_sha256']}")
        print(f"Freeze SHA256: {candidate['freeze_sha256']}")
        print(f"Cohort SHA256: {candidate['cohort_results_sha256']}")
        print(f"Baseline rules SHA256: {candidate['baseline_rules_sha256']}")
        print(f"Runtime signer SHA256: {public_key_fingerprint(args.runtime_public.read_bytes())}")
        print(f"Runtime: {args.runtime_id}; target: {args.target_vm}; interface: {args.interface}")
        print("Mandatory rollback: yes; maximum activation window: 300 seconds")
        print("No production activation is authorized; candidate remains review-only.")
        if input(f"Type exactly '{PROMPT}' to authorize signing: ").strip() != PROMPT:
            parser.error("owner confirmation was not given")
        password = getpass.getpass("Owner encrypted signing key passphrase: ").encode()
        authorization = build_frozen_owner_authorization(
            candidate, replay, replay_public_pem=replay_public,
            owner_private_pem=args.owner_private.read_bytes(), owner_private_password=password,
            owner_public_pem=owner_public, runtime_public_pem=args.runtime_public.read_bytes(),
            approver_identity=args.approver_identity,
            isolated_root=args.isolated_root, runtime_id=args.runtime_id,
            target_vm=args.target_vm, interface=args.interface, nonce=secrets.token_hex(16),
        )
        _write_exclusive(args.output, authorization)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(f"Frozen owner authorization saved: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
