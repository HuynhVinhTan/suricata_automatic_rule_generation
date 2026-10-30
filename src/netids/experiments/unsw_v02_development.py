"""UNSW v02 group-disjoint ML/DL development.

Invoked exclusively through netids.experiments.run.
Reuses existing model implementations and plotting modules.
"""

import hashlib
import json
from pathlib import Path

import joblib
import numpy as np

from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from netids.adapters.unsw import FEATURES, load_unsw_csv
from netids.evaluation.dl_plots import save_dl_figures
from netids.evaluation.research_plots import save_development_figures
from netids.experiments import unsw_ml_development as ml
from netids.experiments import unsw_dl_development as dl
from netids.experiments import unsw_group_split as grouped
from netids.models.dl import NumpyMLP
from netids.models.autoencoder import NumpyAutoencoder


OUTPUT = Path("artifacts/experiments/unsw_v02_development")

SOURCE_FILES = (
    "src/netids/experiments/run.py",
    "src/netids/experiments/unsw_v02_development.py",
    "src/netids/experiments/unsw_group_split.py",
    "src/netids/experiments/unsw_ml_development.py",
    "src/netids/experiments/unsw_dl_development.py",
    "src/netids/models/dl.py",
    "src/netids/models/autoencoder.py",
    "src/netids/adapters/unsw.py",
    "src/netids/evaluation/research_plots.py",
    "src/netids/evaluation/dl_plots.py",
)


def sha256(path):
    digest = hashlib.sha256()

    with Path(path).open("rb") as stream:
        for chunk in iter(
            lambda: stream.read(1024 * 1024),
            b"",
        ):
            digest.update(chunk)

    return digest.hexdigest()


def validate_inputs():
    if sha256(ml.TRAIN_FILE) != ml.EXPECTED_TRAIN_SHA256:
        raise ValueError("Official UNSW training CSV hash changed")

    split_file = grouped.OUTPUT / "split_indices.npz"

    manifest = json.loads(
        (grouped.OUTPUT / "manifest.json").read_text(
            encoding="utf-8"
        )
    )

    if (
        manifest.get("experiment") != "unsw_group_split_v02"
        or manifest.get("train_sha256")
        != ml.EXPECTED_TRAIN_SHA256
        or manifest.get("split_sha256") != sha256(split_file)
        or manifest.get("exact_feature_group_overlap") != 0
        or manifest.get("feature_names") != list(FEATURES)
    ):
        raise ValueError("Invalid v02 partition manifest")

    data = load_unsw_csv(ml.TRAIN_FILE)

    with np.load(split_file, allow_pickle=False) as splits:
        dev = splits["development"].astype(np.int64)
        val = splits["validation"].astype(np.int64)
        cal = splits["calibration"].astype(np.int64)

    joined = np.concatenate((dev, val, cal))

    if not np.array_equal(
        np.sort(joined),
        np.arange(len(data.y)),
    ):
        raise ValueError(
            "v02 indices missing, overlapping or out of range"
        )

    _, group_ids = np.unique(
        data.X,
        axis=0,
        return_inverse=True,
    )

    for left, right in (
        (dev, val),
        (dev, cal),
        (val, cal),
    ):
        if np.intersect1d(
            group_ids[left],
            group_ids[right],
        ).size:
            raise ValueError("v02 feature groups overlap")

    for name, indices in (
        ("development", dev),
        ("validation", val),
        ("calibration", cal),
    ):
        if (
            len(indices) != manifest["partitions"][name]["rows"]
            or np.unique(data.y[indices]).size != 2
        ):
            raise ValueError(
                "v02 partition class count mismatch"
            )

    return data, dev, val, cal, sha256(split_file)


def supervised_metrics(y, scores):
    labels = (scores >= 0.5).astype(np.int8)

    tn, fp, fn, tp = map(
        int,
        confusion_matrix(
            y, labels, labels=[0, 1]
        ).ravel(),
    )

    return {
        "precision_at_0_5": float(
            precision_score(y, labels, zero_division=0)
        ),
        "recall_at_0_5": float(
            recall_score(y, labels, zero_division=0)
        ),
        "f1_at_0_5": float(
            f1_score(y, labels, zero_division=0)
        ),
        "fpr_at_0_5": fp / (tn + fp),
        "confusion_at_0_5": {
            "tn": tn,
            "fp": fp,
            "fn": fn,
            "tp": tp,
        },
    }


def run():
    if OUTPUT.exists():
        raise FileExistsError(
            "v02 development already exists; use --stage report"
        )

    data, dev, val, cal, split_hash = validate_inputs()

    X, y = data.X, data.y
    y_val = y[val]

    print(
        "=== UNSW V02 FEATURE-DISJOINT ML/DL DEVELOPMENT ===",
        flush=True,
    )
    print(
        f"Development={len(dev)} "
        f"Validation={len(val)} "
        f"Reserved calibration={len(cal)}",
        flush=True,
    )
    print("Official UNSW test: NOT ACCESSED", flush=True)

    candidates = []
    all_scores = {}
    selected = {}
    models = {}
    histories = {}
    ml_plot_items = []

    def accept(
        name,
        family,
        model,
        scaler,
        score,
        history=None,
    ):
        score = np.asarray(
            score,
            dtype=np.float64,
        ).reshape(-1)

        if (
            score.shape != y_val.shape
            or not np.isfinite(score).all()
        ):
            raise ValueError(
                "Invalid validation scores: " + name
            )

        ap = float(
            average_precision_score(y_val, score)
        )

        record = {
            "name": name,
            "family": family,
            "validation_ap": ap,
        }

        if family != "AE":
            if np.any((score < 0) | (score > 1)):
                raise ValueError(
                    "Invalid classifier probabilities"
                )

            record.update(
                supervised_metrics(y_val, score)
            )
        else:
            if np.any(score < 0):
                raise ValueError(
                    "Negative reconstruction error"
                )

            record["threshold_status"] = "NOT_CALIBRATED"

        if history is not None:
            record["epochs_executed"] = len(
                history["train_loss"]
            )

        candidates.append(record)
        all_scores[name] = score

        if (
            family not in selected
            or ap > selected[family]["validation_ap"]
        ):
            selected[family] = {
                "name": name,
                "validation_ap": ap,
                "threshold_status": "NOT_CALIBRATED",
            }

            models[family] = {
                "model": model,
                "scaler": scaler,
                "features": list(FEATURES),
                "family": family,
            }

            if history is not None:
                histories[family] = {
                    key: [float(v) for v in values]
                    for key, values in history.items()
                }

        if family == "AE":
            print(
                f"  {name}: AP={ap:.6f} "
                "(threshold pending)",
                flush=True,
            )
        else:
            print(
                f"  {name}: AP={ap:.6f} "
                f"F1@0.5={record['f1_at_0_5']:.4f} "
                f"FPR@0.5={record['fpr_at_0_5']:.4f}",
                flush=True,
            )

        return record

    print(
        "--- ML candidates: existing ml.candidates() ---",
        flush=True,
    )

    for name, model in ml.candidates():
        model.fit(X[dev], y[dev])

        scores = np.asarray(
            model.predict_proba(X[val])[:, 1],
            dtype=np.float64,
        )

        family = (
            "RF" if name.startswith("RF_")
            else "LogReg"
        )

        record = accept(
            name, family, model, None, scores
        )

        ml_plot_items.append({
            "name": name,
            "scores": scores,
            "ap": record["validation_ap"],
            "f1": record["f1_at_0_5"],
        })

    print("--- Supervised NumPy MLP ---", flush=True)

    mlp_scaler = StandardScaler().fit(X[dev])
    X_dev_mlp = mlp_scaler.transform(X[dev])
    X_val_mlp = mlp_scaler.transform(X[val])

    for name, h1, h2 in (
        ("MLP_16x8", 16, 8),
        ("MLP_24x12", 24, 12),
    ):
        model = NumpyMLP(
            input_dim=4,
            hidden1=h1,
            hidden2=h2,
            epochs=50,
            batch_size=256,
            patience=8,
            random_state=42,
        )

        model.fit(
            X_dev_mlp,
            y[dev],
            X_val_mlp,
            y_val,
        )

        scores = dl.positive_probability(
            model.predict_proba(X_val_mlp),
            len(val),
        )

        accept(
            name,
            "MLP",
            model,
            mlp_scaler,
            scores,
            model.history_,
        )

    print(
        "--- Normal-only NumPy Autoencoder ---",
        flush=True,
    )

    normal_dev = dev[y[dev] == 0]

    ae_train, ae_early = train_test_split(
        normal_dev,
        test_size=0.20,
        random_state=42,
    )

    ae_scaler = StandardScaler().fit(X[ae_train])

    X_ae_train = ae_scaler.transform(X[ae_train])
    X_ae_early = ae_scaler.transform(X[ae_early])
    X_ae_val = ae_scaler.transform(X[val])

    print("AE normal train:", len(ae_train), flush=True)
    print("AE early stopping:", len(ae_early), flush=True)

    for name, hidden, bottleneck in (
        ("AE_8x2", 8, 2),
        ("AE_12x3", 12, 3),
    ):
        model = NumpyAutoencoder(
            input_dim=4,
            hidden_dim=hidden,
            bottleneck_dim=bottleneck,
            epochs=60,
            batch_size=256,
            patience=8,
            random_state=42,
        )

        model.fit(X_ae_train, X_ae_early)

        scores = np.asarray(
            model.anomaly_score(X_ae_val)
        ).reshape(-1)

        accept(
            name,
            "AE",
            model,
            ae_scaler,
            scores,
            model.history_,
        )

    # Save only after all training runs complete.
    OUTPUT.mkdir(parents=True, exist_ok=False)

    figure_dir = OUTPUT / "figures"

    ml_figures = save_development_figures(
        ml_plot_items,
        y_val,
        figure_dir / "ml",
    )

    dl_figures = save_dl_figures(
        figure_dir / "dl",
        histories,
        y_val,
        all_scores[selected["MLP"]["name"]],
        all_scores[selected["AE"]["name"]],
    )

    for family, item in selected.items():
        file = OUTPUT / (
            "model_" + family.lower() + ".joblib"
        )

        joblib.dump(models[family], file)

        item["model_file"] = file.name
        item["model_sha256"] = sha256(file)

    order = list(all_scores)

    np.savez_compressed(
        OUTPUT / "validation_scores.npz",
        names=np.asarray(order),
        scores=np.column_stack([
            all_scores[name] for name in order
        ]),
        labels=y_val.astype(np.int8),
        original_source_rows=(
            data.source_row_indices[val]
        ),
    )

    with (
        OUTPUT / "training_history.json"
    ).open("x", encoding="utf-8") as stream:
        json.dump(histories, stream, indent=2)

    summary = {
        "experiment": "unsw_v02_development",
        "status": "DEVELOPMENT_ONLY",
        "dataset": "UNSW-NB15",
        "seed": 42,
        "official_test_accessed": False,
        "reserved_calibration_used": False,
        "train_sha256": ml.EXPECTED_TRAIN_SHA256,
        "shared_split_sha256": split_hash,
        "feature_names": list(FEATURES),
        "dev_rows": len(dev),
        "validation_rows": len(val),
        "reserved_calibration_rows": len(cal),
        "ae_train_normal_rows": len(ae_train),
        "ae_early_normal_rows": len(ae_early),
        "validation_attack_prevalence": float(
            np.mean(y_val)
        ),
        "selection_metric": (
            "validation_average_precision"
        ),
        "candidates": candidates,
        "selected": selected,
        "figures": (
            ["ml/" + name for name in ml_figures]
            + ["dl/" + name for name in dl_figures]
        ),
        "validation_scores_sha256": sha256(
            OUTPUT / "validation_scores.npz"
        ),
        "history_sha256": sha256(
            OUTPUT / "training_history.json"
        ),
        "source_sha256": {
            name: sha256(name)
            for name in SOURCE_FILES
        },
        "limitations": [
            "Feature-group-disjoint, not host/time-disjoint.",
            "MLP early stopping and hyperparameter selection both use validation.",
            "Threshold 0.5 is provisional for supervised classifiers.",
            "Autoencoder has no calibrated decision threshold.",
            "No official UNSW test accessed.",
        ],
    }

    with (
        OUTPUT / "summary.json"
    ).open("x", encoding="utf-8") as stream:
        json.dump(summary, stream, indent=2)
        stream.write("\n")

    print("\n=== SELECTED MODELS BY VALIDATION AP ===")

    for family, item in selected.items():
        print(
            f"{family}: {item['name']} "
            f"AP={item['validation_ap']:.6f}"
        )

    print("Figures:", len(summary["figures"]))
    print("PASS: UNSW V02 ML/DL DEVELOPMENT")
    print("OFFICIAL TEST NOT ACCESSED")
    print("CALIBRATION NOT USED FOR FITTING/SELECTION")


def verify():
    summary = json.loads(
        (OUTPUT / "summary.json").read_text(
            encoding="utf-8"
        )
    )

    if (
        summary.get("experiment")
        != "unsw_v02_development"
        or summary.get("status")
        != "DEVELOPMENT_ONLY"
        or summary.get("official_test_accessed") is not False
        or summary.get("reserved_calibration_used") is not False
        or summary.get("train_sha256")
        != ml.EXPECTED_TRAIN_SHA256
        or summary.get("shared_split_sha256")
        != sha256(
            grouped.OUTPUT / "split_indices.npz"
        )
    ):
        raise ValueError(
            "Invalid UNSW v02 report provenance"
        )

    scores_path = OUTPUT / "validation_scores.npz"

    if sha256(scores_path) != summary[
        "validation_scores_sha256"
    ]:
        raise ValueError(
            "Validation predictions checksum mismatch"
        )

    with np.load(
        scores_path,
        allow_pickle=False,
    ) as rows:
        names = rows["names"].tolist()
        matrix = rows["scores"]
        y = rows["labels"]
        sources = rows["original_source_rows"]

    if (
        matrix.shape != (
            summary["validation_rows"],
            len(names),
        )
        or len(sources) != len(y)
        or not np.isfinite(matrix).all()
    ):
        raise ValueError(
            "Saved validation predictions contract mismatch"
        )

    records = summary["candidates"]

    if names != [
        record["name"] for record in records
    ]:
        raise ValueError("Candidate order mismatch")

    for col, record in enumerate(records):
        measured = average_precision_score(
            y,
            matrix[:, col],
        )

        if not np.isclose(
            measured,
            record["validation_ap"],
            atol=1e-10,
            rtol=0,
        ):
            raise ValueError(
                "AP mismatch for " + record["name"]
            )

        if record["family"] != "AE":
            values = supervised_metrics(
                y,
                matrix[:, col],
            )

            for key in (
                "f1_at_0_5",
                "fpr_at_0_5",
                "precision_at_0_5",
                "recall_at_0_5",
            ):
                if not np.isclose(
                    values[key],
                    record[key],
                    atol=1e-10,
                    rtol=0,
                ):
                    raise ValueError(
                        "Metric mismatch: "
                        + record["name"]
                        + " "
                        + key
                    )

            if (
                values["confusion_at_0_5"]
                != record["confusion_at_0_5"]
            ):
                raise ValueError(
                    "Confusion matrix mismatch: "
                    + record["name"]
                )

    for family, item in summary["selected"].items():
        if sha256(
            OUTPUT / item["model_file"]
        ) != item["model_sha256"]:
            raise ValueError(
                "Model file hash mismatch: " + family
            )

    if sha256(
        OUTPUT / "training_history.json"
    ) != summary["history_sha256"]:
        raise ValueError(
            "Training history hash mismatch"
        )

    for figure in summary["figures"]:
        path = OUTPUT / "figures" / figure

        if not (
            path.is_file()
            and path.suffix == ".png"
        ):
            raise ValueError(
                "Missing PNG: " + figure
            )

        with path.open("rb") as stream:
            if stream.read(8) != b"\x89PNG\r\n\x1a\n":
                raise ValueError(
                    "Bad PNG header: " + figure
                )

    print(
        "=== VERIFIED UNSW V02 GROUP-DISJOINT DEVELOPMENT ==="
    )

    for family, item in summary["selected"].items():
        print(
            f"{family}: {item['name']} "
            f"AP={item['validation_ap']:.6f}"
        )

    print(
        "Validation attack prevalence:",
        round(
            summary["validation_attack_prevalence"],
            6,
        ),
    )

    print(
        "Figures verified:",
        len(summary["figures"]),
    )

    print("PASS: UNSW V02 DEVELOPMENT VERIFIED")
    print("NO TRAINING PERFORMED")
    print("NO FILES MODIFIED")