"""Register existing ML-generated Suricata artifacts for human review only.

No approval, rule transfer, Suricata reload, or deployment occurs.
Hashes must be pinned independently by the operator, not inferred at runtime.
"""

from __future__ import annotations

import argparse
import json
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
    args = parser.parse_args(argv)
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
        )
    except (LifecycleError, OSError, ValueError) as exc:
        print(json.dumps({"status": "REJECTED", "reason": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
