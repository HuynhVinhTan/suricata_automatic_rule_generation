"""Canonical experiment CLI for Suricata AI IDS."""

import argparse
import csv
import hashlib
import importlib
import json
from pathlib import Path

import numpy as np
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)


EXPERIMENT_MODULES = {
    "unsw-nb15": "netids.experiments.unsw_ml_development",
}


def file_sha256(path):
    digest = hashlib.sha256()

    with Path(path).open("rb") as stream:
        for chunk in iter(
            lambda: stream.read(1024 * 1024), b""
        ):
            digest.update(chunk)

    return digest.hexdigest()


def verify_development(module):
    """Read-only verification of existing development artifacts."""

    root = module.OUTPUT_DIR

    summary = json.loads(
        (root / "summary.json").read_text(
            encoding="utf-8"
        )
    )

    if (
        summary.get("experiment") != "unsw_ml_dev_v01"
        or summary.get("status") != "DEVELOPMENT_ONLY"
        or summary.get("official_test_accessed") is not False
        or summary.get("dataset_sha256")
        != module.EXPECTED_TRAIN_SHA256
        or summary.get("selection_metric")
        != "average_precision_validation"
    ):
        raise ValueError(
            "Unexpected development report contract"
        )

    model_path = (
        root / "selected_development_model.joblib"
    )

    if (
        file_sha256(model_path)
        != summary["selected_model_sha256"]
    ):
        raise ValueError("Saved model SHA256 mismatch")

    with np.load(
        root / "split_indices.npz",
        allow_pickle=False,
    ) as split:
        dev = split["development"]
        val = split["validation"]
        cal = split["calibration"]

        all_indices = np.concatenate(
            (dev, val, cal)
        )

        if (
            len(dev) != summary["dev_rows"]
            or len(val) != summary["validation_rows"]
            or len(cal)
            != summary["reserved_calibration_rows"]
            or len(all_indices)
            != summary["accepted_train_rows"]
            or not np.array_equal(
                np.sort(all_indices),
                np.arange(len(all_indices)),
            )
        ):
            raise ValueError(
                "Development split integrity mismatch"
            )

    predictions_path = (
        root / "validation_predictions.csv"
    )

    with predictions_path.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as stream:
        rows = list(csv.DictReader(stream))

    if len(rows) != len(val):
        raise ValueError(
            "Validation prediction count mismatch"
        )

    y = np.asarray([
        int(row["true_label"])
        for row in rows
    ])

    scores = np.asarray([
        float(row["attack_score"])
        for row in rows
    ])

    stored_predictions = np.asarray([
        int(row["predicted_at_0_5"])
        for row in rows
    ])

    calculated_predictions = (
        scores >= 0.5
    ).astype(int)

    if (
        not np.isin(y, [0, 1]).all()
        or not np.isfinite(scores).all()
        or not (
            (scores >= 0) & (scores <= 1)
        ).all()
        or not np.array_equal(
            stored_predictions,
            calculated_predictions,
        )
    ):
        raise ValueError(
            "Invalid validation predictions"
        )

    selected = next(
        (
            result
            for result in summary["results"]
            if result["name"]
            == summary["selected_model"]
        ),
        None,
    )

    if selected is None:
        raise ValueError(
            "Selected model missing from report"
        )

    tn, fp, fn, tp = map(
        int,
        confusion_matrix(
            y,
            stored_predictions,
            labels=[0, 1],
        ).ravel(),
    )

    computed_metrics = {
        "ap": average_precision_score(
            y, scores
        ),
        "precision": precision_score(
            y, stored_predictions, zero_division=0
        ),
        "recall": recall_score(
            y, stored_predictions, zero_division=0
        ),
        "f1": f1_score(
            y, stored_predictions, zero_division=0
        ),
        "fpr": fp / (fp + tn),
    }

    for name, actual in computed_metrics.items():
        if not np.isclose(
            actual,
            float(selected[name]),
            rtol=0,
            atol=1e-10,
        ):
            raise ValueError(
                f"Stored metric mismatch: {name}"
            )

    counts = {
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "tp": tp,
    }

    for name, actual in counts.items():
        if int(selected[name]) != actual:
            raise ValueError(
                f"Confusion matrix mismatch: {name}"
            )

    for filename in summary["figures"]:
        if (
            Path(filename).name != filename
            or not filename.endswith(".png")
        ):
            raise ValueError(
                "Invalid figure filename"
            )

        figure = module.FIGURE_DIR / filename

        with figure.open("rb") as stream:
            signature = stream.read(8)

        if signature != b"\x89PNG\r\n\x1a\n":
            raise ValueError(
                f"Invalid PNG figure: {filename}"
            )

    print("\n=== VERIFIED DEVELOPMENT REPORT ===")
    print("Experiment:", summary["experiment"])
    print("Dataset:", summary["dataset"])
    print("Selected model:", summary["selected_model"])

    print(
        "Validation AP:",
        f"{computed_metrics['ap']:.6f}",
    )

    print(
        "Validation F1@0.5:",
        f"{computed_metrics['f1']:.6f}",
    )

    print(
        "Validation FPR@0.5:",
        f"{computed_metrics['fpr']:.6f}",
    )

    print(
        "Confusion matrix [TN FP FN TP]:",
        tn, fp, fn, tp,
    )

    print("Figures verified:", len(summary["figures"]))
    print("Model SHA256:", file_sha256(model_path))

    print("\nPASS: UNSW DEVELOPMENT ARTIFACTS VERIFIED")
    print("OFFICIAL TEST NOT ACCESSED")
    print("NO TRAINING PERFORMED")
    print("NO FILES MODIFIED")


def dispatch(dataset, stage, family="ml", version="v01"):
    if dataset not in EXPERIMENT_MODULES:
        raise ValueError(
            f"Unsupported dataset: {dataset}"
        )

    if version == "v02":
        if family != "all" or stage not in ("develop", "report", "calibrate", "audit", "test"):
            raise ValueError(
                "v02 supports --family all with develop/report only"
            )

        from netids.experiments import unsw_v02_development as v02

        if stage == "develop":
            v02.run()
        elif stage == "calibrate":
            from netids.experiments import unsw_v02_calibration as calibration
            calibration.run()
        elif stage == "audit":
            from netids.evaluation import unsw_v02_overfit as audit
            audit.run()
        elif stage == "test":
            from netids.experiments import unsw_v02_official_test as official
            official.run()
            official.verify()
        else:
            from netids.experiments import unsw_v02_official_test as official
            if official.OUTPUT.exists():
                official.verify()
            else:
                v02.verify()

        return

    if family == "all":
        raise ValueError("--family all requires --version v02")

    if stage == "prepare":
        from netids.experiments.unsw_group_split import prepare
        prepare()
        return

    if stage in ("calibrate", "test"):
        raise NotImplementedError(
            f"Stage '{stage}' is not implemented: "
            "model/threshold not frozen"
        )

    if family == "dl":
        from netids.experiments import unsw_dl_development as dl

        if stage == "develop":
            dl.run()
        elif stage == "report":
            dl.verify()
        else:
            raise ValueError("Unsupported DL stage")
        return

    module = importlib.import_module(
        EXPERIMENT_MODULES[dataset]
    )

    if stage == "report":
        verify_development(module)

    elif stage == "develop":
        if (
            module.OUTPUT_DIR.exists()
            or module.FIGURE_DIR.exists()
        ):
            raise FileExistsError(
                "Development run already exists. "
                "Use --stage report. "
                "Never overwrite existing experiments."
            )

        module.main()

    else:
        raise ValueError(
            f"Unsupported stage: {stage}"
        )


def main():
    parser = argparse.ArgumentParser(
        description=__doc__
    )

    parser.add_argument(
        "--dataset",
        required=True,
        choices=sorted(EXPERIMENT_MODULES),
    )

    parser.add_argument(
        "--stage",
        required=True,
        choices=(
            "prepare",
            "develop",
            "calibrate",
            "audit",
            "test",
            "report",
        ),
    )

    parser.add_argument(
        "--family",
        choices=("ml", "dl", "all"),
        default="ml",
    )

    parser.add_argument(
        "--version",
        choices=("v01", "v02"),
        default="v01",
    )

    args = parser.parse_args()

    dispatch(args.dataset, args.stage, args.family, args.version)


if __name__ == "__main__":
    main()