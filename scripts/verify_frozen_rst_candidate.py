#!/usr/bin/env python3
"""Verify frozen RST candidate evidence without deployment or activation."""

import argparse
import json
from pathlib import Path

from netids.rst_candidate_verification import verify_frozen_rst_candidate


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--freeze", type=Path, required=True)
    parser.add_argument("--development-evidence", type=Path, required=True)
    parser.add_argument("--holdout-report", type=Path, required=True)
    parser.add_argument("--cohort-results", type=Path, required=True)
    parser.add_argument("--cohort-plan", type=Path, required=True)
    parser.add_argument("--rule", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--sid", type=int, default=9103005)
    parser.add_argument("--freeze-sha256")
    parser.add_argument("--cohort-sha256")
    args = parser.parse_args(argv)
    result = verify_frozen_rst_candidate(
        freeze_path=args.freeze,
        development_evidence_path=args.development_evidence,
        holdout_report_path=args.holdout_report,
        cohort_results_path=args.cohort_results,
        cohort_plan_path=args.cohort_plan,
        rule_path=args.rule,
        metadata_path=args.metadata,
        expected_source_commit=args.source_commit,
        expected_sid=args.sid,
        expected_freeze_sha256=args.freeze_sha256,
        expected_cohort_sha256=args.cohort_sha256,
    )
    result.pop("rule", None)
    result.pop("metadata", None)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
