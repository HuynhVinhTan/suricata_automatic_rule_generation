#!/usr/bin/env python3
"""Prepare unsigned frozen replay evidence from verified existing G4 artifacts."""

import argparse
import json
import os
from pathlib import Path

from netids.g5_frozen_candidate import (
    FrozenCandidateError,
    build_frozen_candidate,
    prepare_frozen_replay_evidence,
    verify_frozen_candidate,
)
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
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--freeze", type=Path, required=True)
    parser.add_argument("--development-evidence", type=Path, required=True)
    parser.add_argument("--holdout-report", type=Path, required=True)
    parser.add_argument("--cohort-results", type=Path, required=True)
    parser.add_argument("--cohort-plan", type=Path, required=True)
    parser.add_argument("--rule", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--freeze-sha256", required=True)
    parser.add_argument("--cohort-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output.exists() or args.output.is_symlink():
        parser.error("replay evidence output exists; never overwrite")
    try:
        candidate = json.loads(args.candidate.read_text(encoding="utf-8"))
        verify_frozen_candidate(candidate, candidate.get("baseline_comparison"))
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
        rebuilt = build_frozen_candidate(verification, candidate["baseline_comparison"])
        if rebuilt["candidate_id"] != candidate["candidate_id"]:
            raise FrozenCandidateError("verified source artifacts do not reproduce candidate identity")
        holdout = json.loads(args.holdout_report.read_text(encoding="utf-8"))
        cohort = json.loads(args.cohort_results.read_text(encoding="utf-8"))
        metadata = json.loads(args.metadata.read_text(encoding="utf-8"))
        evidence = prepare_frozen_replay_evidence(candidate, holdout, cohort, metadata)
        _write_exclusive(args.output, evidence)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(json.dumps({
        "status": "frozen_replay_evidence_prepared",
        "schema_version": evidence["schema_version"],
        "candidate_id": evidence["candidate_id"],
        "cohort_case_count": len(evidence["cohort_cases"]),
        "signed": False,
        "approved": False,
        "deployed": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
