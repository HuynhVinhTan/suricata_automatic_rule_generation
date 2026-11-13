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


def _read(path: Path) -> pd.DataFrame:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not rows:
        raise ValueError(f"empty dataset: {path}")
    return pd.DataFrame([row["features"] for row in rows])[list(FEATURE_COLUMNS)], np.array([row["label"] for row in rows])


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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--development", type=Path, required=True)
    parser.add_argument("--calibration", type=Path, required=True)
    parser.add_argument("--holdout", type=Path, required=True)
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    X_dev, y_dev = _read(args.development)
    X_cal, y_cal = _read(args.calibration)
    X_hold, y_hold = _read(args.holdout)
    if set(y_dev) != {0, 1} or set(y_cal) != {0, 1} or set(y_hold) != {0, 1}:
        raise ValueError("each split must contain both classes")
    model = make_ml_pipeline("logistic_regression", random_state=42)
    model.fit(X_dev, y_dev)
    cal_scores = model.predict_proba(X_cal)[:, 1]
    candidates = sorted({0.0, 0.5, 1.0, *map(float, cal_scores)})
    threshold = max(candidates, key=lambda candidate: (_metrics(y_cal, cal_scores, candidate)["F1"], -candidate))
    hold_scores = model.predict_proba(X_hold)[:, 1]
    report = {"schema_version": SCHEMA_VERSION, "profile": "showcase_demo", "demo_only": True,
              "development": {"records": int(len(y_dev))}, "calibration": {"records": int(len(y_cal)), "threshold": threshold, "metrics": _metrics(y_cal, cal_scores, threshold)},
              "holdout": {"records": int(len(y_hold)), "metrics": _metrics(y_hold, hold_scores, threshold)},
              "created_utc": datetime.now(timezone.utc).isoformat()}
    args.artifact_dir.mkdir(parents=True, exist_ok=False)
    model_path = args.artifact_dir / "pipeline.joblib"
    joblib.dump(model, model_path, compress=3)
    report["model_sha256"] = _sha(model_path)
    metadata = {"artifact_version": 1, "status": "demo_only", "demo_only": True, "model_name": "logistic_regression",
                "schema_version": SCHEMA_VERSION, "feature_columns": list(FEATURE_COLUMNS), "sklearn_version": sklearn.__version__,
                "training_records": int(len(y_dev)), "decision_threshold": threshold, "created_utc": report["created_utc"],
                "model_sha256": report["model_sha256"],
                "source_dataset": {"development_manifest_sha256": _sha(args.development), "calibration_manifest_sha256": _sha(args.calibration), "holdout_manifest_sha256": _sha(args.holdout)},
                "threshold_provenance": {"decision_threshold": threshold, "status": "demo_only", "calibration_manifest_sha256": _sha(args.calibration)}}
    (args.artifact_dir / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
