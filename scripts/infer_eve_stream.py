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
    parser.add_argument("--max-queue-size", type=int, default=1024)
    parser.add_argument("--poll-interval", type=float, default=0.25)
    parser.add_argument("--once", action="store_true", help="Process currently complete lines and exit")
    args = parser.parse_args()

    model, metadata = load_ml_artifact(args.model_dir)
    worker = StreamingInferenceWorker(
        reader=JsonlEveReader(args.input),
        model=FlowModelAdapter(model, metadata),
        output_path=args.output,
        run_id=args.run_id,
        window_seconds=args.window_seconds,
        max_queue_size=args.max_queue_size,
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
