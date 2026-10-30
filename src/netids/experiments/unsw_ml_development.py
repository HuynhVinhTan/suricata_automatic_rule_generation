"""UNSW-NB15 supervised ML development experiment.

Reads ONLY the official training CSV.
Does not use the official testing CSV.
Does not modify previously trained CTU or lab models.
"""

import csv
import hashlib
import json
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from netids.adapters.unsw import FEATURES, load_unsw_csv
from netids.evaluation.research_plots import (
    save_development_figures,
)


SEED = 42
EXPECTED_TRAIN_SHA256 = (
    "bec7dd5ec88dc2a0ccc7a07879d338395ed7421750f675fd0339e07dfe0648fa"
)

TRAIN_FILE = Path(
    "data/raw/unsw-nb15/UNSW_NB15_training-set.csv"
)

OUTPUT_DIR = Path(
    "artifacts/experiments/unsw_ml_dev_v01"
)

FIGURE_DIR = Path(
    "artifacts/figures/unsw_ml_dev_v01"
)


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def candidates():
    return [
        (
            "LogReg_C0.1",
            make_pipeline(
                StandardScaler(),
                LogisticRegression(
                    C=0.1,
                    class_weight="balanced",
                    max_iter=1000,
                    random_state=SEED,
                ),
            ),
        ),
        (
            "LogReg_C1.0",
            make_pipeline(
                StandardScaler(),
                LogisticRegression(
                    C=1.0,
                    class_weight="balanced",
                    max_iter=1000,
                    random_state=SEED,
                ),
            ),
        ),
        (
            "RF_leaf1",
            RandomForestClassifier(
                n_estimators=120,
                max_depth=16,
                min_samples_leaf=1,
                class_weight="balanced_subsample",
                random_state=SEED,
                n_jobs=-1,
            ),
        ),
        (
            "RF_leaf5",
            RandomForestClassifier(
                n_estimators=120,
                max_depth=16,
                min_samples_leaf=5,
                class_weight="balanced_subsample",
                random_state=SEED,
                n_jobs=-1,
            ),
        ),
    ]


def main():
    print("=== UNSW ML DEVELOPMENT ===", flush=True)

    if OUTPUT_DIR.exists() or FIGURE_DIR.exists():
        raise FileExistsError(
            "Experiment output already exists; refusing overwrite"
        )

    actual_sha = sha256(TRAIN_FILE)

    if actual_sha != EXPECTED_TRAIN_SHA256:
        raise ValueError("Official training CSV SHA256 mismatch")

    data = load_unsw_csv(TRAIN_FILE)

    X, y = data.X, data.y
    indices = np.arange(len(y))

    # Approximately 70% development, 15% model selection
    # validation and 15% reserved calibration.
    dev_idx, remaining_idx = train_test_split(
        indices,
        test_size=0.30,
        stratify=y,
        random_state=SEED,
    )

    val_idx, cal_idx = train_test_split(
        remaining_idx,
        test_size=0.50,
        stratify=y[remaining_idx],
        random_state=SEED,
    )

    assert not (
        set(dev_idx) & set(val_idx)
        or set(dev_idx) & set(cal_idx)
        or set(val_idx) & set(cal_idx)
    )

    assert (
        len(dev_idx) + len(val_idx) + len(cal_idx)
        == len(y)
    )

    print("Official train accepted:", len(y), flush=True)
    print("Development:", len(dev_idx), flush=True)
    print("Validation:", len(val_idx), flush=True)
    print("Reserved calibration:", len(cal_idx), flush=True)
    print("Official test: NOT ACCESSED", flush=True)

    X_dev, y_dev = X[dev_idx], y[dev_idx]
    X_val, y_val = X[val_idx], y[val_idx]

    results = []
    best_model = None
    best_name = None
    best_ap = -1.0

    for name, model in candidates():
        print(f"Training: {name}", flush=True)

        model.fit(X_dev, y_dev)
        scores = model.predict_proba(X_val)[:, 1]

        ap = float(average_precision_score(y_val, scores))
        labels = (scores >= 0.5).astype(int)

        cm = confusion_matrix(
            y_val, labels, labels=[0, 1]
        )

        tn, fp, fn, tp = map(int, cm.ravel())

        record = {
            "name": name,
            "ap": ap,
            "precision": float(
                precision_score(y_val, labels, zero_division=0)
            ),
            "recall": float(
                recall_score(y_val, labels, zero_division=0)
            ),
            "f1": float(
                f1_score(y_val, labels, zero_division=0)
            ),
            "fpr": fp / (fp + tn),
            "tn": tn,
            "fp": fp,
            "fn": fn,
            "tp": tp,
            "scores": scores,
        }

        results.append(record)

        print(
            f"  AP={ap:.4f} "
            f"F1@0.5={record['f1']:.4f} "
            f"Recall={record['recall']:.4f} "
            f"FPR={record['fpr']:.4f}",
            flush=True,
        )

        if ap > best_ap:
            best_ap = ap
            best_name = name
            best_model = model

    OUTPUT_DIR.mkdir(parents=True, exist_ok=False)

    np.savez_compressed(
        OUTPUT_DIR / "split_indices.npz",
        development=dev_idx,
        validation=val_idx,
        calibration=cal_idx,
    )

    figure_names = save_development_figures(
        results, y_val, FIGURE_DIR
    )

    selected = next(
        item for item in results
        if item["name"] == best_name
    )

    with (OUTPUT_DIR / "validation_predictions.csv").open(
        "x", newline="", encoding="utf-8"
    ) as stream:
        writer = csv.writer(stream)
        writer.writerow([
            "original_source_row",
            "true_label",
            "attack_score",
            "predicted_at_0_5",
        ])

        for idx, true_label, score in zip(
            val_idx,
            y_val,
            selected["scores"],
        ):
            writer.writerow([
                int(data.source_row_indices[idx]),
                int(true_label),
                float(score),
                int(score >= 0.5),
            ])

    model_path = OUTPUT_DIR / "selected_development_model.joblib"
    joblib.dump(best_model, model_path)

    summary = {
        "experiment": "unsw_ml_dev_v01",
        "status": "DEVELOPMENT_ONLY",
        "seed": SEED,
        "dataset": "UNSW-NB15",
        "dataset_sha256": actual_sha,
        "feature_names": list(FEATURES),
        "accepted_train_rows": int(len(y)),
        "dev_rows": int(len(dev_idx)),
        "validation_rows": int(len(val_idx)),
        "reserved_calibration_rows": int(len(cal_idx)),
        "official_test_accessed": False,
        "split_method": "stratified_random_within_official_train",
        "split_limitation": (
            "May retain correlated flows across partitions; "
            "not a host- or time-disjoint evaluation."
        ),
        "selection_metric": "average_precision_validation",
        "selected_model": best_name,
        "selected_model_sha256": sha256(model_path),
        "provisional_threshold": 0.5,
        "results": [
            {
                key: value
                for key, value in item.items()
                if key != "scores"
            }
            for item in results
        ],
        "figures": figure_names,
        "notes": (
            "No official test used. Model is development-only. "
            "Threshold 0.5 is not final calibrated threshold. "
            "AP is average precision, not trapezoidal PR-AUC."
        ),
    }

    with (OUTPUT_DIR / "summary.json").open(
        "x", encoding="utf-8"
    ) as stream:
        json.dump(summary, stream, indent=2)
        stream.write("\n")

    print("\n=== MODEL SELECTION ===")
    print("Selected by validation AP:", best_name)
    print("Validation AP:", round(best_ap, 6))
    print("Model SHA256:", sha256(model_path))
    print("Report:", OUTPUT_DIR / "summary.json")
    print("Figures:", FIGURE_DIR)
    print("PASS: UNSW ML DEVELOPMENT EXPERIMENT")
    print("OFFICIAL TEST NOT ACCESSED")


if __name__ == "__main__":
    main()