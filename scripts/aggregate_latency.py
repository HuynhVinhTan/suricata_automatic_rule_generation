#!/usr/bin/env python3
"""Aggregate verified latency trace evidence without inventing missing values."""

import argparse
from pathlib import Path

from netids.latency_aggregation import LatencyEvidenceError, aggregate_latency


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, action="append", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = aggregate_latency(args.evidence, args.output_dir)
    except (LatencyEvidenceError, OSError) as exc:
        parser.error(str(exc))
    print(f"Accepted latency runs: {result['accepted_runs']}")
    print(f"Measured observations: {result['measured_observations']}")
    print(f"Output directory: {result['output_dir']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
