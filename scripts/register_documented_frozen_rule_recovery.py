"""Register the pinned documented-frozen rule as a review-only candidate."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from netids.lifecycle_integration import register_documented_frozen_candidate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--replay-manifest", type=Path, required=True)
    parser.add_argument("--expected-replay-manifest-sha256", required=True)
    parser.add_argument("--source-pcap", type=Path, required=True)
    parser.add_argument("--calibration-manifest", type=Path, required=True)
    parser.add_argument("--decision-manifest", type=Path)
    parser.add_argument("--audit-path", type=Path, required=True)
    parser.add_argument("--isolated-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output.is_symlink() or args.output.exists():
        parser.error("Candidate output exists: never overwrite or replay a candidate")
    result = register_documented_frozen_candidate(
        repo_root=args.repo_root, evidence_path=args.evidence,
        replay_manifest=args.replay_manifest,
        expected_replay_manifest_sha256=args.expected_replay_manifest_sha256,
        source_pcap=args.source_pcap,
        calibration_manifest=args.calibration_manifest,
        decision_manifest=args.decision_manifest,
        audit_path=args.audit_path, isolated_root=args.isolated_root,
        return_private_candidate=True,
    )
    candidate = result["candidate"]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(candidate, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        args.output.unlink(missing_ok=True)
        raise
    print(json.dumps(result["summary"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
