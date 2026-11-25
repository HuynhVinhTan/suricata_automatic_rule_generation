#!/usr/bin/env python3
"""Generate H17/H18 figures from verified offline latency aggregation CSVs."""

import argparse
from pathlib import Path

from netids.latency_figures import plot_latency_figures


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--per-run", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--coverage", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    result = plot_latency_figures(args.per_run, args.summary, args.coverage, args.output_dir)
    print(f"Figure status: {result['status']}")
    print(f"Generated figures: {len(result['generated'])}")
    print(f"Pending figures: {len(result['pending'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
