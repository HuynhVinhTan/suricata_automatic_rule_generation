"""Train and calibrate the isolated EVE-native showcase model."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score

from netids.features.schema import FEATURE_COLUMNS, SCHEMA_VERSION
from netids.models.ml import make_ml_pipeline


def _read_rows(path: Path) -> list[dict]:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not rows:
        raise ValueError(f"empty dataset: {path}")
    return rows


def validate_split_disjointness(splits: dict[str, list[dict]]) -> None:
    for field in ("run_id", "attempt_id", "event_sha256"):
        seen = {}
        for split, rows in splits.items():
            for row in rows:
                value = row.get(field)
                if value in seen and seen[value] != split:
                    name = {"run_id": "session", "attempt_id": "attempt", "event_sha256": "event"}[field]
                    raise ValueError(f"{name} overlap between {seen[value]} and {split}: {value}")
                seen[value] = split


def _read(path: Path) -> tuple[pd.DataFrame, np.ndarray, list[dict]]:
    rows = _read_rows(path)
    eligible = [row for row in rows if row.get("binary_eligible") is True and row.get("label") in (0, 1)]
    if not eligible:
        raise ValueError(f"no binary-eligible records: {path}")
    return (pd.DataFrame([row["features"] for row in eligible])[list(FEATURE_COLUMNS)],
            np.array([row["label"] for row in eligible]), rows)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _metrics(y, scores, threshold):
    pred = (scores >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {"TP": int(tp), "FN": int(fn), "FP": int(fp), "TN": int(tn),
            "precision": float(precision_score(y, pred, zero_division=0)),
            "recall": float(recall_score(y, pred, zero_division=0)),
            "F1": float(f1_score(y, pred, zero_division=0)),
            "FPR": float(fp / (fp + tn)) if fp + tn else 0.0}


def session_metrics(rows: list[dict], scores, threshold: float) -> dict:
    grouped = {}
    eligible_rows = [row for row in rows if row.get("binary_eligible") is True]
    for row, score in zip(eligible_rows, scores):
        item = grouped.setdefault(row["run_id"], {"scenario": row["scenario"], "max_score": 0.0})
        item["max_score"] = max(item["max_score"], float(score))
    attacks = [item for item in grouped.values() if item["scenario"] == "ATTACK"]
    normals = [item for item in grouped.values() if item["scenario"] == "NORMAL"]
    attack_detected = sum(item["max_score"] >= threshold for item in attacks)
    normal_false_alerts = sum(item["max_score"] >= threshold for item in normals)
    return {
        "attack_sessions": len(attacks), "attack_detected": attack_detected,
        "attack_session_detection_rate": attack_detected / len(attacks) if attacks else 0.0,
        "normal_sessions": len(normals), "normal_false_alerts": normal_false_alerts,
        "normal_session_false_alert_rate": normal_false_alerts / len(normals) if normals else 0.0,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--development", type=Path, required=True)
    parser.add_argument("--calibration", type=Path, required=True)
    parser.add_argument("--holdout", type=Path, required=True)
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    X_dev, y_dev, dev_rows = _read(args.development)
    X_cal, y_cal, cal_rows = _read(args.calibration)
    X_hold, y_hold, hold_rows = _read(args.holdout)
    validate_split_disjointness({"development": dev_rows, "calibration": cal_rows, "holdout": hold_rows})
    if set(y_dev) != {0, 1} or set(y_cal) != {0, 1} or set(y_hold) != {0, 1}:
        raise ValueError("each split must contain both classes")
    model = make_ml_pipeline("logistic_regression", random_state=42)
    model.fit(X_dev, y_dev)
    cal_scores = model.predict_proba(X_cal)[:, 1]
    candidates = sorted({0.0, 0.5, 1.0, *map(float, cal_scores)})
    threshold = max(candidates, key=lambda candidate: (_metrics(y_cal, cal_scores, candidate)["F1"], -candidate))
    hold_scores = model.predict_proba(X_hold)[:, 1]
    split_plan = {"development": {"sessions": sorted({row["run_id"] for row in dev_rows}), "records": len(dev_rows)},
                  "calibration": {"sessions": sorted({row["run_id"] for row in cal_rows}), "records": len(cal_rows)},
                  "holdout": {"sessions": sorted({row["run_id"] for row in hold_rows}), "records": len(hold_rows)}}
    report = {"schema_version": SCHEMA_VERSION, "profile": "showcase_demo", "demo_only": True,
              "split_plan": split_plan, "development": {"records": int(len(y_dev))}, "calibration": {"records": int(len(y_cal)), "threshold": threshold, "metrics": _metrics(y_cal, cal_scores, threshold)},
              "holdout": {"records": int(len(y_hold)), "metrics": _metrics(y_hold, hold_scores, threshold), "session_metrics": session_metrics(hold_rows, hold_scores, threshold)},
              "created_utc": datetime.now(timezone.utc).isoformat()}
    args.artifact_dir.mkdir(parents=True, exist_ok=False)
    model_path = args.artifact_dir / "pipeline.joblib"
    joblib.dump(model, model_path, compress=3)
    report["model_sha256"] = _sha(model_path)
    metadata = {"artifact_version": 1, "status": "demo_only", "demo_only": True, "profile": "showcase_demo", "model_name": "logistic_regression",
                "schema_version": SCHEMA_VERSION, "feature_columns": list(FEATURE_COLUMNS), "sklearn_version": sklearn.__version__,
                "training_records": int(len(y_dev)), "decision_threshold": threshold, "created_utc": report["created_utc"],
                "model_sha256": report["model_sha256"],
                "source_dataset": {"development_manifest_sha256": _sha(args.development), "calibration_manifest_sha256": _sha(args.calibration), "holdout_manifest_sha256": _sha(args.holdout), "split_plan": split_plan, "split_disjointness": "verified"},
                "calibration_method": "max_f1_on_calibration", "calibration_version": "showcase-calibration-v1",
                "threshold_provenance": {"decision_threshold": threshold, "status": "demo_only", "calibration_method": "max_f1_on_calibration", "calibration_version": "showcase-calibration-v1", "calibration_manifest_sha256": _sha(args.calibration)}}
    (args.artifact_dir / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
