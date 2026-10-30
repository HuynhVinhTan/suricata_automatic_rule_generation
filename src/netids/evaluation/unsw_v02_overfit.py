"""Read-only overfitting diagnostics for frozen UNSW v02 models."""

import json

import joblib
import numpy as np

from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    recall_score,
)

from netids.experiments import unsw_v02_development as v02
from netids.experiments import unsw_v02_calibration as cal


def measures(y, scores, threshold):
    y = np.asarray(y)
    scores = np.asarray(scores, dtype=float).reshape(-1)

    if (
        y.shape != scores.shape
        or not np.isfinite(scores).all()
        or set(np.unique(y).tolist()) != {0, 1}
        or not np.isfinite(threshold)
    ):
        raise ValueError("Invalid overfitting audit inputs")

    pred = (scores >= threshold).astype(int)

    tn, fp, fn, tp = map(
        int,
        confusion_matrix(y, pred, labels=[0, 1]).ravel(),
    )

    return {
        "ap": float(average_precision_score(y, scores)),
        "fpr": fp / (tn + fp),
        "recall": float(recall_score(y, pred)),
        "f1": float(f1_score(y, pred, zero_division=0)),
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "tp": tp,
    }


def run():
    print("=== VERIFY FROZEN CALIBRATION ===", flush=True)

    cal.verify()
    v02.verify()

    data, dev, val, reserved, split_hash = (
        v02.validate_inputs()
    )

    summary = json.loads(
        (v02.OUTPUT / "summary.json").read_text(
            encoding="utf-8"
        )
    )

    calibration = json.loads(
        (cal.OUTPUT / "manifest.json").read_text(
            encoding="utf-8"
        )
    )

    if (
        split_hash != calibration["split_sha256"]
        or len(reserved) != summary["reserved_calibration_rows"]
        or calibration["official_test_accessed"] is not False
    ):
        raise ValueError("Experiment provenance mismatch")

    with np.load(
        v02.OUTPUT / "validation_scores.npz",
        allow_pickle=False,
    ) as saved:
        names = saved["names"].tolist()
        validation_scores = saved["scores"].copy()
        saved_labels = saved["labels"].copy()
        source_rows = saved["original_source_rows"].copy()

    if (
        not np.array_equal(saved_labels, data.y[val])
        or not np.array_equal(
            source_rows,
            data.source_row_indices[val],
        )
    ):
        raise ValueError("Validation row alignment mismatch")

    histories = json.loads(
        (v02.OUTPUT / "training_history.json").read_text(
            encoding="utf-8"
        )
    )

    print("\n=== TRAIN VS FEATURE-DISJOINT VALIDATION ===")
    print("Development rows:", len(dev))
    print("Validation rows:", len(val))
    print("Calibration rows: NOT SCORED IN THIS AUDIT")
    print("Official test: NOT ACCESSED")

    loaded_models = {}

    for family in ("LogReg", "RF", "MLP", "AE"):
        selected = summary["selected"][family]
        frozen = calibration["models"][family]

        model_path = v02.OUTPUT / selected["model_file"]

        if (
            v02.sha256(model_path) != selected["model_sha256"]
            or frozen["frozen_model_sha256"]
            != selected["model_sha256"]
        ):
            raise ValueError("Frozen model checksum mismatch")

        # Trusted local artifacts created by our own training pipeline.
        bundle = joblib.load(model_path)
        loaded_models[family] = bundle["model"]

        train_scores = cal.score_model(
            family, bundle, data.X[dev]
        )

        live_validation_scores = cal.score_model(
            family, bundle, data.X[val]
        )

        selected_name = selected["name"]

        if selected_name not in names:
            raise ValueError("Selected validation scores missing")

        stored_scores = validation_scores[
            :, names.index(selected_name)
        ]

        if not np.allclose(
            live_validation_scores,
            stored_scores,
            rtol=0,
            atol=1e-10,
        ):
            raise ValueError(
                "Saved and frozen-model scores disagree"
            )

        threshold = float(frozen["threshold"])

        train_metrics = measures(
            data.y[dev], train_scores, threshold
        )

        val_metrics = measures(
            data.y[val], stored_scores, threshold
        )

        if not np.isclose(
            val_metrics["ap"],
            selected["validation_ap"],
            rtol=0,
            atol=1e-10,
        ):
            raise ValueError(
                "Validation AP provenance mismatch"
            )

        ap_gap = (
            train_metrics["ap"] - val_metrics["ap"]
        )

        print(f"\n--- {family}: {selected_name} ---")
        print("Frozen threshold:", f"{threshold:.12g}")

        print(
            "AP Train/Validation:",
            f"{train_metrics['ap']:.6f} / "
            f"{val_metrics['ap']:.6f}",
        )

        print("AP gap Train - Validation:", f"{ap_gap:+.6f}")

        print(
            "FPR Train/Validation:",
            f"{train_metrics['fpr']:.4%} / "
            f"{val_metrics['fpr']:.4%}",
        )

        print(
            "Recall Train/Validation:",
            f"{train_metrics['recall']:.4%} / "
            f"{val_metrics['recall']:.4%}",
        )

        print(
            "F1 Train/Validation:",
            f"{train_metrics['f1']:.6f} / "
            f"{val_metrics['f1']:.6f}",
        )

        print(
            "Validation TN FP FN TP:",
            val_metrics["tn"],
            val_metrics["fp"],
            val_metrics["fn"],
            val_metrics["tp"],
        )

        # Diagnostic signals, not formal statistical
        # proof or universal acceptance thresholds.
        if ap_gap > 0.03:
            print("REVIEW: AP generalization gap above 0.03")

        if val_metrics["fpr"] > 0.01:
            print(
                "REVIEW: Validation FPR exceeds the "
                "1% calibration target"
            )

    print("\n=== DEEP LEARNING LOSS HISTORY ===")

    for family, monitoring_key in (
        ("MLP", "val_loss"),
        ("AE", "cal_loss"),
    ):
        history = histories[family]

        train_loss = np.asarray(
            history["train_loss"], dtype=float
        )

        monitor_loss = np.asarray(
            history[monitoring_key], dtype=float
        )

        if (
            train_loss.ndim != 1
            or train_loss.size == 0
            or train_loss.shape != monitor_loss.shape
            or not np.isfinite(train_loss).all()
            or not np.isfinite(monitor_loss).all()
        ):
            raise ValueError(
                "Invalid DL loss history: " + family
            )

        best_index = int(np.argmin(monitor_loss))
        model = loaded_models[family]

        print(f"\n--- {family} ---")
        print("Epochs recorded:", len(train_loss))
        print("Best monitored epoch (1-based):", best_index + 1)
        print(
            "Saved best_epoch attribute:",
            getattr(model, "best_epoch_", "UNKNOWN"),
        )
        print(
            "Train loss first/last:",
            f"{train_loss[0]:.8f} / {train_loss[-1]:.8f}",
        )
        print(
            "Monitored loss best/last:",
            f"{monitor_loss[best_index]:.8f} / "
            f"{monitor_loss[-1]:.8f}",
        )
        print(
            "Monitored loss rise after best:",
            f"{monitor_loss[-1] - monitor_loss[best_index]:.8f}",
        )

    print("\nPASS: UNSW V02 OVERFITTING DIAGNOSTIC")
    print("DIAGNOSTIC ONLY - NOT AN OVERFITTING-FREE CERTIFICATE")
    print("NO MODEL TRAINING OR THRESHOLD TUNING")
    print("NO OFFICIAL TEST SCORING")
    print("NO EXPERIMENT ARTIFACTS MODIFIED")