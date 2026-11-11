"""Run the read-only streaming dataset quality audit."""

import argparse
import json
from pathlib import Path

from netids.dataset_audit import profile_csv


DATASETS = {
    "UNSW_NB15": {
        "glob": "data/raw/unsw-nb15/*.csv",
        "features": ["dur", "spkts", "dpkts", "sbytes", "dbytes"],
        "labels": ["label"],
    },
    "CIC_IDS2017": {
        "glob": "data/raw/cic-ids2017/*.csv",
        "features": ["Flow Duration", "Total Fwd Packets", "Total Backward Packets", "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Flow Bytes/s", "Flow Packets/s"],
        "labels": ["Label"],
    },
    "CTU_13": {
        "glob": "data/raw/ctu-13/*.binetflow",
        "features": ["Dur", "TotPkts", "TotBytes", "SrcBytes"],
        "labels": ["Label"],
        "timestamps": ["StartTime"],
    },
}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path("."))
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts/audits/dataset-quality-20261112"))
    args = parser.parse_args(argv)
    root = args.project_root.resolve()
    results = []
    for name, spec in DATASETS.items():
        paths = sorted(root.glob(spec["glob"]))
        if not paths:
            results.append({"dataset": name, "status": "MISSING"})
            continue
        for path in paths:
            relative_path = path.relative_to(root).as_posix()
            relative = relative_path.replace("/", "_")
            try:
                report = profile_csv(
                    path,
                    args.output_dir / relative,
                    feature_columns=spec["features"],
                    label_columns=spec["labels"],
                    timestamp_columns=spec.get("timestamps", ()),
                )
                result = dict(report)
                result.update({"dataset": name, "status": report["audit_status"], "path": relative_path})
                results.append(result)
            except (OSError, ValueError) as exc:
                results.append({"dataset": name, "status": "BLOCKED", "path": relative_path, "error": str(exc)})
    args.output_dir.mkdir(parents=True, exist_ok=True)
    summary = {
        "audit": "streaming_read_only_dataset_quality_v2",
        "source_files_unchanged": True,
        "temporary_root": str(Path(args.output_dir).resolve()),
        "datasets": results,
        "limitations": [
            "Exact feature equality does not prove shared sessions or host/time leakage.",
            "CIC suitability remains conditional/fail for new model training because non-finite rate values and duplicate headers require an explicit adapter policy.",
        ],
    }
    (args.output_dir / "quality_summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    lines = ["# Dataset quality audit", "", "| Dataset | Status | Path | Records | SHA256 |", "|---|---|---|---:|---|"]
    for item in results:
        lines.append(f"| {item['dataset']} | {item['status']} | `{item.get('path', '')}` | {item.get('record_count', '')} | `{item.get('sha256', '')}` |")
    (args.output_dir / "quality_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output_dir), "datasets": len(results)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
