"""One-shot official UNSW-NB15 test of frozen v02 models."""

import json
from pathlib import Path

import joblib
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from netids.adapters.unsw import load_unsw_csv
from netids.experiments import unsw_v02_development as v02
from netids.experiments import unsw_v02_calibration as cal
from netids.evaluation.unsw_final_plots import save_final_figures


TEST_FILE = Path(
    "data/raw/unsw-nb15/UNSW_NB15_testing-set.csv"
)
TEST_SHA256 = (
    "734fe6642edf758f7c94d7d9149426b49d202fe8e7bf0bef47392489c3c0a559"
)
OUTPUT = Path(
    "artifacts/experiments/unsw_v02_official_test_v01"
)
FAMILIES = ("LogReg", "RF", "MLP", "AE")


def metrics(y, scores, threshold):
    y = np.asarray(y)
    scores = np.asarray(scores, dtype=np.float64).reshape(-1)

    if (
        y.ndim != 1
        or y.shape != scores.shape
        or set(np.unique(y).tolist()) != {0, 1}
        or not np.isfinite(scores).all()
        or not np.isfinite(threshold)
    ):
        raise ValueError("Invalid final-test metric inputs")

    predicted = (scores >= threshold).astype(np.int8)

    tn, fp, fn, tp = map(
        int,
        confusion_matrix(
            y, predicted, labels=[0, 1]
        ).ravel(),
    )

    return {
        "ap": float(average_precision_score(y, scores)),
        "roc_auc": float(roc_auc_score(y, scores)),
        "accuracy": float(accuracy_score(y, predicted)),
        "precision": float(
            precision_score(y, predicted, zero_division=0)
        ),
        "recall": float(
            recall_score(y, predicted, zero_division=0)
        ),
        "f1": float(
            f1_score(y, predicted, zero_division=0)
        ),
        "fpr": float(fp / (fp + tn)),
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "tp": tp,
    }


def fingerprint_rows(X):
    matrix = np.ascontiguousarray(
        X, dtype=np.float64
    )
    return matrix.view(
        np.dtype((np.void, matrix.shape[1] * 8))
    ).reshape(-1)


def preflight():
    if OUTPUT.exists():
        raise FileExistsError(
            "Official test was already started; refusing repeat"
        )

    if (
        not TEST_FILE.is_file()
        or cal.sha256(TEST_FILE) != TEST_SHA256
    ):
        raise ValueError("Official UNSW test SHA256 mismatch")

    cal.verify()
    v02.verify()

    development = json.loads(
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
        calibration.get("primary_model_family") != "RF"
        or calibration.get("fpr_budget") != 0.01
        or calibration.get("official_test_accessed") is not False
        or development.get("official_test_accessed") is not False
        or calibration.get("development_summary_sha256")
        != cal.sha256(v02.OUTPUT / "summary.json")
        or set(calibration.get("models", {})) != set(FAMILIES)
        or set(development.get("selected", {})) != set(FAMILIES)
    ):
        raise ValueError(
            "Frozen experiment policy mismatch"
        )

    for family in FAMILIES:
        selected = development["selected"][family]
        frozen = calibration["models"][family]
        filename = selected["model_file"]

        if (
            Path(filename).name != filename
            or cal.sha256(v02.OUTPUT / filename)
            != selected["model_sha256"]
            or frozen["frozen_model_sha256"]
            != selected["model_sha256"]
            or not np.isfinite(float(frozen["threshold"]))
        ):
            raise ValueError(
                "Frozen model/threshold mismatch: " + family
            )

    return development, calibration


def run():
    development, calibration = preflight()

    # Persistent marker: after this point, the test is consumed.
    # Never rerun this function to improve observed metrics.
    OUTPUT.mkdir(parents=True, exist_ok=False)

    intent = {
        "status": "OFFICIAL_TEST_STARTED",
        "test_sha256": TEST_SHA256,
        "development_summary_sha256": cal.sha256(
            v02.OUTPUT / "summary.json"
        ),
        "calibration_manifest_sha256": cal.sha256(
            cal.OUTPUT / "manifest.json"
        ),
        "primary_model": "RF",
        "frozen_fpr_budget": 0.01,
        "families": list(FAMILIES),
        "no_test_driven_tuning": True,
    }

    with (OUTPUT / "intent.json").open(
        "x", encoding="utf-8"
    ) as stream:
        json.dump(intent, stream, indent=2)
        stream.write("\n")

    data = load_unsw_csv(TEST_FILE)

    if (
        data.original_rows != 82332
        or data.included_rows != 72513
        or data.X.shape != (72513, 4)
        or int(np.count_nonzero(data.y == 0)) != 35945
        or int(np.count_nonzero(data.y == 1)) != 36568
    ):
        raise ValueError("Unexpected official test cohort")

    scores_by_family = {}
    thresholds = {}
    results = {}

    print("\n=== UNSW OFFICIAL TEST - FROZEN V02 ===")
    print("Test rows:", len(data.y))
    print("Normal:", 35945)
    print("Attack:", 36568)
    print("Models: FROZEN")
    print("Thresholds: FROZEN")
    print("Retraining: DISABLED")

    for family in FAMILIES:
        selected = development["selected"][family]
        frozen = calibration["models"][family]

        model_path = v02.OUTPUT / selected["model_file"]

        # Only hash-verified local models created by this project.
        bundle = joblib.load(model_path)

        scores = cal.score_model(
            family, bundle, data.X
        )

        threshold = float(frozen["threshold"])
        measured = metrics(data.y, scores, threshold)

        scores_by_family[family] = scores
        thresholds[family] = threshold

        results[family] = {
            "model": selected["name"],
            "model_sha256": selected["model_sha256"],
            "validation_ap": selected["validation_ap"],
            "frozen_threshold": threshold,
            "calibration_normal_fpr": frozen[
                "observed_normal_fpr"
            ],
            **measured,
        }

        print(
            f"{family}: AP={measured['ap']:.6f} "
            f"F1={measured['f1']:.4f} "
            f"Recall={measured['recall']:.4%} "
            f"FPR={measured['fpr']:.4%} "
            f"TN={measured['tn']} FP={measured['fp']} "
            f"FN={measured['fn']} TP={measured['tp']}",
            flush=True,
        )

    score_path = OUTPUT / "official_test_scores.npz"

    np.savez_compressed(
        score_path,
        families=np.asarray(FAMILIES),
        scores=np.column_stack([
            scores_by_family[name]
            for name in FAMILIES
        ]),
        labels=data.y.astype(np.int8),
        original_source_rows=(
            data.source_row_indices.astype(np.int64)
        ),
    )

    # Descriptive diagnostic only: no model selection or tuning.
    from netids.experiments import unsw_ml_development as ml

    training = load_unsw_csv(ml.TRAIN_FILE)

    overlap = int(np.count_nonzero(
        np.isin(
            fingerprint_rows(data.X),
            np.unique(fingerprint_rows(training.X)),
        )
    ))

    rf_pred = (
        scores_by_family["RF"] >= thresholds["RF"]
    )

    categories = np.asarray(
        data.attack_categories, dtype=str
    )

    attack_details = {}

    for category in sorted(
        np.unique(categories[data.y == 1])
    ):
        mask = (
            (data.y == 1)
            & (categories == category)
        )

        attack_details[str(category)] = {
            "attack_rows": int(mask.sum()),
            "rf_detected": int(
                np.count_nonzero(rf_pred[mask])
            ),
            "rf_recall": float(
                np.mean(rf_pred[mask])
            ),
        }

    figures = save_final_figures(
        OUTPUT / "figures",
        data.y,
        scores_by_family,
        thresholds,
    )

    report = {
        "experiment": "unsw_v02_official_test_v01",
        "status": "OFFICIAL_TEST_COMPLETED_FROZEN",
        "official_test_scored": True,
        "test_sha256": TEST_SHA256,
        "test_original_rows": data.original_rows,
        "test_tcp_udp_rows": data.included_rows,
        "test_normal_rows": 35945,
        "test_attack_rows": 36568,
        "test_attack_prevalence": float(np.mean(data.y)),
        "test_rows_matching_official_train_feature_vector": overlap,
        "test_feature_vector_overlap_rate": float(
            overlap / len(data.y)
        ),
        "primary_model_family": "RF",
        "frozen_calibration_fpr_budget": 0.01,
        "intent_sha256": cal.sha256(
            OUTPUT / "intent.json"
        ),
        "scores_sha256": cal.sha256(score_path),
        "development_summary_sha256": intent[
            "development_summary_sha256"
        ],
        "calibration_manifest_sha256": intent[
            "calibration_manifest_sha256"
        ],
        "results": results,
        "rf_recall_by_attack_category": attack_details,
        "figure_sha256": {
            name: cal.sha256(
                OUTPUT / "figures" / name
            )
            for name in figures
        },
        "limitations": [
            "Official test is now consumed; no test-driven tuning.",
            "TCP/UDP subset with four engineered features only.",
            "No evidence of zero-day detection from these labels alone.",
            "Exact feature overlap does not prove shared traffic sessions.",
            "Test FPR is not a live deployment guarantee.",
            "Internal feature-disjoint validation is not host/time-disjoint.",
        ],
    }

    with (OUTPUT / "report.json").open(
        "x", encoding="utf-8"
    ) as stream:
        json.dump(
            report, stream, indent=2,
            ensure_ascii=False
        )
        stream.write("\n")

    print(
        "Official test rows matching train feature vectors:",
        overlap,
    )
    print(
        "Feature-vector overlap rate:",
        f"{overlap / len(data.y):.2%}",
    )
    print("\nPASS: OFFICIAL TEST COMPLETED")
    print("Report:", OUTPUT / "report.json")
    print("TEST CONSUMED - DO NOT RE-TUNE")


def verify():
    report = json.loads(
        (OUTPUT / "report.json").read_text(
            encoding="utf-8"
        )
    )

    if (
        report.get("status")
        != "OFFICIAL_TEST_COMPLETED_FROZEN"
        or report.get("official_test_scored") is not True
        or report.get("test_sha256") != TEST_SHA256
        or report.get("primary_model_family") != "RF"
        or report.get("intent_sha256")
        != cal.sha256(OUTPUT / "intent.json")
        or report.get("scores_sha256")
        != cal.sha256(
            OUTPUT / "official_test_scores.npz"
        )
        or report.get("calibration_manifest_sha256")
        != cal.sha256(
            cal.OUTPUT / "manifest.json"
        )
        or report.get("development_summary_sha256")
        != cal.sha256(
            v02.OUTPUT / "summary.json"
        )
    ):
        raise ValueError("Final report provenance mismatch")

    with np.load(
        OUTPUT / "official_test_scores.npz",
        allow_pickle=False,
    ) as saved:
        names = saved["families"].tolist()
        scores = saved["scores"]
        labels = saved["labels"]
        row_indices = saved["original_source_rows"]

    if (
        names != list(FAMILIES)
        or scores.shape != (72513, 4)
        or labels.shape != (72513,)
        or row_indices.shape != (72513,)
        or not np.isfinite(scores).all()
    ):
        raise ValueError("Final prediction contract mismatch")

    for col, family in enumerate(FAMILIES):
        stored = report["results"][family]

        measured = metrics(
            labels, scores[:, col],
            stored["frozen_threshold"],
        )

        for key, value in measured.items():
            if not np.isclose(
                value, stored[key],
                rtol=0, atol=1e-10,
            ):
                raise ValueError(
                    f"Final metric mismatch: {family}/{key}"
                )

        model_path = (
            v02.OUTPUT
            / ("model_" + family.lower() + ".joblib")
        )

        if cal.sha256(model_path) != stored["model_sha256"]:
            raise ValueError(
                "Frozen model hash mismatch: " + family
            )

    for name, checksum in report["figure_sha256"].items():
        path = OUTPUT / "figures" / name

        if cal.sha256(path) != checksum:
            raise ValueError("Figure checksum mismatch: " + name)

        with path.open("rb") as stream:
            if stream.read(8) != b"\x89PNG\r\n\x1a\n":
                raise ValueError("Invalid PNG: " + name)

    print("\n=== VERIFIED OFFICIAL UNSW TEST REPORT ===")

    for family in FAMILIES:
        record = report["results"][family]
        print(
            f"{family}: AP={record['ap']:.6f} "
            f"F1={record['f1']:.4f} "
            f"Recall={record['recall']:.4%} "
            f"FPR={record['fpr']:.4%}"
        )

    print("PASS: FINAL REPORT VERIFIED")
    print("NO TEST RESCORING")
    print("NO MODEL RETRAINING")
    print("NO FILES MODIFIED")