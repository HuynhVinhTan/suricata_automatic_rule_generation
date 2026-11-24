#!/usr/bin/env python3
"""Sign an independently reviewed six-case frozen RST replay attestation."""

import argparse
import getpass
import json
import os
from pathlib import Path

from netids.g5_frozen_candidate import sign_frozen_replay_attestation, verify_frozen_candidate


def _write_exclusive(path, value):
    if path.exists() or path.is_symlink():
        raise ValueError("attestation output exists; never overwrite")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--replay-private", type=Path, required=True)
    parser.add_argument("--replay-public", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output.exists() or args.output.is_symlink():
        parser.error("attestation exists; never overwrite")
    try:
        candidate = json.loads(args.candidate.read_text(encoding="utf-8"))
        evidence = json.loads(args.evidence.read_text(encoding="utf-8"))
        verify_frozen_candidate(candidate, candidate.get("baseline_comparison"))
        if evidence.get("cohort_cases") != candidate.get("cohort_cases"):
            raise ValueError("runtime evidence does not bind the exact six-case cohort")
        for key in ("candidate_id", "sid", "rule_file_sha256", "freeze_sha256", "cohort_results_sha256", "baseline_rules_sha256"):
            if evidence.get(key) != candidate.get(key):
                raise ValueError(f"runtime evidence mismatch: {key}")
        password = getpass.getpass("Replay encrypted signing key passphrase: ").encode()
        signed = sign_frozen_replay_attestation(
            candidate, evidence, args.replay_private.read_bytes(), password
        )
        _write_exclusive(args.output, signed)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(f"Frozen replay attestation saved: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
