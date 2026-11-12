"""Recover the accepted rule from the pinned Git evidence document.

This command does not recover or recreate historical generated metadata.  It
only emits an explicitly labelled documented-source recovery record.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from netids.documented_rule_recovery import recover_documented_frozen_rule
from netids.trusted_replay import (
    DOCUMENTED_EVIDENCE_GIT_BLOB_SHA,
    DOCUMENTED_EVIDENCE_PATH,
    RULE_SHA,
)


def _exclusive_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, default=None)
    parser.add_argument("--rule-output", type=Path, required=True)
    parser.add_argument("--provenance-output", type=Path, required=True)
    args = parser.parse_args(argv)
    evidence = args.evidence or args.repo_root / DOCUMENTED_EVIDENCE_PATH
    if args.rule_output.exists() or args.provenance_output.exists():
        parser.error("Refusing to overwrite recovery artifacts")
    recovered = recover_documented_frozen_rule(
        repo_root=args.repo_root,
        evidence_path=evidence,
        evidence_git_blob_sha=DOCUMENTED_EVIDENCE_GIT_BLOB_SHA,
        expected_rule_sha256=RULE_SHA,
    )
    _exclusive_bytes(args.rule_output, recovered["rule_file_bytes"])
    _exclusive_bytes(
        args.provenance_output,
        (json.dumps(recovered["provenance"], indent=2, sort_keys=True) + "\n").encode(),
    )
    print(json.dumps({
        "status": "RECOVERED_FROM_DOCUMENTED_FROZEN_SOURCE",
        "rule_sha256": recovered["rule_sha256"],
        "rule_file_sha256": recovered["rule_file_sha256"],
        "historical_generated_metadata": "unavailable_not_recovered",
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
