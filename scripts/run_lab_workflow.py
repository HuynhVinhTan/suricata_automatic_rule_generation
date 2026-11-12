#!/usr/bin/env python3
"""Run the supported review-only EVE-to-inference laboratory workflow."""

import argparse
from pathlib import Path

from netids.eve_worker import FlowModelAdapter, JsonlEveReader, StreamingInferenceWorker
from netids.lab_workflow import run_streaming_lab_workflow
from netids.models.artifacts import load_ml_artifact


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--model-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()

    model, metadata = load_ml_artifact(args.model_dir)
    worker = StreamingInferenceWorker(
        reader=JsonlEveReader(args.input),
        model=FlowModelAdapter(model, metadata),
        output_path=args.output,
        run_id=args.run_id,
    )
    report = run_streaming_lab_workflow(worker, args.evidence)
    print(f"overall_status={report['overall_status']}")
    print(f"processed_events={report['stages']['continuous_inference']['status']}")
    print(f"evidence={args.evidence}")


if __name__ == "__main__":
    main()
