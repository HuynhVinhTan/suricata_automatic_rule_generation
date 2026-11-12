#!/usr/bin/env python3
"""Continuously infer compatible Suricata EVE flow events.

This command is review-only. It never generates, approves, stages or loads
Suricata rules and it leaves the Filebeat/ELK input untouched.
"""

import argparse
import json
from pathlib import Path

from netids.eve_worker import FlowModelAdapter, JsonlEveReader, StreamingInferenceWorker
from netids.models.artifacts import load_ml_artifact


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="Suricata EVE JSONL file")
    parser.add_argument("--model-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--window-seconds", type=int, default=10)
    parser.add_argument("--max-records-per-cycle", type=int, default=1024)
    parser.add_argument("--max-bytes-per-cycle", type=int, default=4 * 1024 * 1024)
    parser.add_argument("--processing-time-budget-seconds", type=float)
    parser.add_argument("--max-chunk-bytes", type=int, default=64 * 1024)
    parser.add_argument("--max-line-bytes", type=int, default=1_000_000)
    parser.add_argument("--window-retention-seconds", type=int)
    parser.add_argument("--max-active-windows", type=int, default=10_000)
    parser.add_argument("--poll-interval", type=float, default=0.25)
    parser.add_argument("--once", action="store_true", help="Process currently complete lines and exit")
    args = parser.parse_args()

    model, metadata = load_ml_artifact(args.model_dir)
    worker = StreamingInferenceWorker(
        reader=JsonlEveReader(args.input, max_chunk_bytes=args.max_chunk_bytes, max_line_bytes=args.max_line_bytes),
        model=FlowModelAdapter(model, metadata),
        output_path=args.output,
        run_id=args.run_id,
        window_seconds=args.window_seconds,
        max_records_per_cycle=args.max_records_per_cycle,
        max_bytes_per_cycle=args.max_bytes_per_cycle,
        processing_time_budget_seconds=args.processing_time_budget_seconds,
        window_retention_seconds=args.window_retention_seconds,
        max_active_windows=args.max_active_windows,
    )
    if args.once:
        result = worker.run_once()
        print(json.dumps({"mode": "once", **result.__dict__}, sort_keys=True))
        return
    try:
        worker.run_forever(poll_interval=args.poll_interval)
    except KeyboardInterrupt:
        worker.request_shutdown()
        print(json.dumps({"mode": "shutdown", "reason": "keyboard_interrupt"}, sort_keys=True))


if __name__ == "__main__":
    main()
