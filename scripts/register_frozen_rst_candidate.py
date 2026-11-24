#!/usr/bin/env python3
"""Import frozen SID9103005 evidence into the versioned G5 bridge."""

import argparse
import json
import os
from pathlib import Path

from netids.g5_frozen_candidate import build_frozen_candidate
from netids.rst_candidate_verification import verify_frozen_rst_candidate


def _write_exclusive(path, value):
    if path.exists() or path.is_symlink():
        raise ValueError("output exists; refusing overwrite")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--freeze", type=Path, required=True)
    parser.add_argument("--development-evidence", type=Path, required=True)
    parser.add_argument("--holdout-report", type=Path, required=True)
    parser.add_argument("--cohort-results", type=Path, required=True)
    parser.add_argument("--cohort-plan", type=Path, required=True)
    parser.add_argument("--rule", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--baseline-comparison", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--freeze-sha256", required=True)
    parser.add_argument("--cohort-sha256", required=True)
    parser.add_argument("--baseline-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output.exists() or args.output.is_symlink():
        parser.error("candidate output exists; never overwrite")
    verification = verify_frozen_rst_candidate(
        freeze_path=args.freeze,
        development_evidence_path=args.development_evidence,
        holdout_report_path=args.holdout_report,
        cohort_results_path=args.cohort_results,
        cohort_plan_path=args.cohort_plan,
        rule_path=args.rule,
        metadata_path=args.metadata,
        expected_source_commit=args.source_commit,
        expected_sid=9103005,
        expected_freeze_sha256=args.freeze_sha256,
        expected_cohort_sha256=args.cohort_sha256,
    )
    baseline = json.loads(args.baseline_comparison.read_text(encoding="utf-8"))
    if not isinstance(baseline, dict):
        parser.error("baseline comparison must be a JSON object")
    baseline_sha = baseline.get("baseline_rules_sha256") or baseline.get(
        "baseline_preflight", {}
    ).get("production", {}).get("rules_sha256")
    if baseline_sha != args.baseline_sha256:
        parser.error("baseline SHA does not match comparison evidence")
    candidate = build_frozen_candidate(verification, baseline)
    _write_exclusive(args.output, candidate)
    print(json.dumps({
        "status": "frozen_candidate_imported",
        "schema_version": candidate["schema_version"],
        "candidate_id": candidate["candidate_id"],
        "sid": candidate["sid"],
        "rule_file_sha256": candidate["rule_file_sha256"],
        "baseline_rules_sha256": candidate["baseline_rules_sha256"],
        "approved": False,
        "deployed": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
