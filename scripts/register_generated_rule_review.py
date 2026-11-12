"""Register existing ML-generated Suricata artifacts for human review only.

No approval, rule transfer, Suricata reload, or deployment occurs.
Hashes must be pinned independently by the operator, not inferred at runtime.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from netids.lifecycle_integration import register_generated_candidate
from netids.rule_lifecycle import LifecycleError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--calibration-manifest", type=Path, required=True)
    parser.add_argument("--expected-calibration-sha256", required=True)
    parser.add_argument("--baseline-rules", type=Path, required=True)
    parser.add_argument("--expected-baseline-sha256", required=True)
    parser.add_argument("--audit-path", type=Path, required=True)
    parser.add_argument("--isolated-root", type=Path, required=True)
    parser.add_argument(
        "--require-candidate-record", action="store_true",
        help="Require candidate_record_v1 provenance; no legacy identity fallback",
    )
    parser.add_argument(
        "--private-candidate-output", type=Path,
        help="Write exact validated candidate for later owner-signed isolated operation",
    )
    args = parser.parse_args(argv)
    if args.private_candidate_output and (
        args.private_candidate_output.is_symlink()
        or args.private_candidate_output.exists()
    ):
        parser.error("Private candidate output exists; never overwrite")
    try:
        result = register_generated_candidate(
            artifact_dir=args.artifact_dir,
            run_id=args.run_id,
            calibration_manifest=args.calibration_manifest,
            expected_calibration_sha256=args.expected_calibration_sha256,
            baseline_rules=args.baseline_rules,
            expected_baseline_sha256=args.expected_baseline_sha256,
            audit_path=args.audit_path,
            isolated_root=args.isolated_root,
            return_private_candidate=bool(args.private_candidate_output),
            require_candidate_record=args.require_candidate_record,
        )
    except (LifecycleError, OSError, ValueError) as exc:
        print(json.dumps({"status": "REJECTED", "reason": str(exc)}, sort_keys=True))
        return 1
    if args.private_candidate_output:
        candidate = result["candidate"]
        path = args.private_candidate_output
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(candidate, stream, indent=2, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
        except Exception:
            path.unlink(missing_ok=True)
            raise
        result = result["summary"]
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
