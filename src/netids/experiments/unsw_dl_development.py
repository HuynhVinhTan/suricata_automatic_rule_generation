"""UNSW-NB15 DL development invoked by the canonical CLI.

Uses the saved ML development/validation split.
Never accesses official test or reserved calibration rows.
"""

import csv
import hashlib
import json
from pathlib import Path

import joblib
import numpy as np
from sklearn.metrics import average_precision_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from netids.adapters.unsw import FEATURES, load_unsw_csv
from netids.experiments import unsw_ml_development as ml
from netids.models.dl import NumpyMLP
from netids.models.autoencoder import NumpyAutoencoder
from netids.evaluation.dl_plots import save_dl_figures


OUTPUT = Path("artifacts/experiments/unsw_dl_dev_v01")
SEED = 42


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(
            lambda: stream.read(1024 * 1024), b""
        ):
            h.update(chunk)
    return h.hexdigest()


def positive_probability(raw, expected_n):
    p = np.asarray(raw, dtype=float)

    if p.shape == (expected_n, 2):
        p = p[:, 1]
    elif p.shape == (expected_n, 1):
        p = p[:, 0]

    if p.shape != (expected_n,) or not np.isfinite(p).all():
        raise ValueError("Invalid MLP prediction shape")

    if np.any((p < 0) | (p > 1)):
        raise ValueError("MLP probability outside [0,1]")

    return p


def calculate_ap(y, scores):
    scores = np.asarray(scores, dtype=float).reshape(-1)

    if scores.shape != y.shape:
        raise ValueError("Score shape mismatch")

    if not np.isfinite(scores).all():
        raise ValueError("Non-finite model scores")

    return float(average_precision_score(y, scores))


def load_development_data():
    if digest(ml.TRAIN_FILE) != ml.EXPECTED_TRAIN_SHA256:
        raise ValueError("UNSW training SHA256 mismatch")

    data = load_unsw_csv(ml.TRAIN_FILE)

    if tuple(FEATURES) != (
        "protocol_tcp",
        "duration_log",
        "packets_log",
        "bytes_log",
    ):
        raise ValueError("Unexpected feature contract")

    ml_summary = json.loads(
        (ml.OUTPUT_DIR / "summary.json").read_text(
            encoding="utf-8"
        )
    )

    if (
        ml_summary.get("official_test_accessed") is not False
        or ml_summary.get("dataset_sha256")
        != ml.EXPECTED_TRAIN_SHA256
    ):
        raise ValueError("ML development provenance mismatch")

    split_path = ml.OUTPUT_DIR / "split_indices.npz"

    with np.load(split_path, allow_pickle=False) as split:
        dev = split["development"].astype(np.int64)
        val = split["validation"].astype(np.int64)
        cal = split["calibration"].astype(np.int64)

    combined = np.concatenate((dev, val, cal))

    if not np.array_equal(
        np.sort(combined),
        np.arange(len(data.y)),
    ):
        raise ValueError("Split overlap or missing indices")

    if (
        len(dev) != ml_summary["dev_rows"]
        or len(val) != ml_summary["validation_rows"]
        or len(cal) != ml_summary["reserved_calibration_rows"]
    ):
        raise ValueError("Saved split/report mismatch")

    return data, dev, val, cal, digest(split_path)


def run():
    if OUTPUT.exists():
        raise FileExistsError(
            "DL development already exists; use --stage report"
        )

    data, dev, val, cal, split_sha = load_development_data()

    X = data.X
    y = data.y
    y_val = y[val]

    if len(np.unique(y_val)) != 2:
        raise ValueError("Validation must contain both classes")

    print("=== UNSW DL DEVELOPMENT ===", flush=True)
    print("Development:", len(dev), flush=True)
    print("Validation:", len(val), flush=True)
    print("Reserved calibration:", len(cal), flush=True)
    print("Official test: NOT ACCESSED", flush=True)

    candidates = []
    winners = {}

    # Supervised MLP: scaler learned exclusively from Development.
    mlp_scaler = StandardScaler().fit(X[dev])
    X_dev_mlp = mlp_scaler.transform(X[dev])
    X_val_mlp = mlp_scaler.transform(X[val])

    for name, h1, h2 in (
        ("MLP_16x8", 16, 8),
        ("MLP_24x12", 24, 12),
    ):
        print("Training:", name, flush=True)

        model = NumpyMLP(
            input_dim=4,
            hidden1=h1,
            hidden2=h2,
            epochs=50,
            batch_size=256,
            patience=8,
            random_state=SEED,
        )

        model.fit(
            X_dev_mlp,
            y[dev],
            X_val_mlp,
            y_val,
        )

        scores = positive_probability(
            model.predict_proba(X_val_mlp),
            len(val),
        )

        ap = calculate_ap(y_val, scores)

        record = {
            "name": name,
            "family": "MLP",
            "validation_ap": ap,
            "epochs_executed": len(model.history_["train_loss"]),
        }
        candidates.append(record)

        if (
            "MLP" not in winners
            or ap > winners["MLP"][0]["validation_ap"]
        ):
            winners["MLP"] = (
                record, model, mlp_scaler, scores
            )

        print(f"  Validation AP: {ap:.6f}", flush=True)

    # Autoencoder: only Normal rows within Development.
    # AE early-stopping rows are separated INSIDE Development.
    # The reserved calibration partition is never accessed.
    normal_dev = dev[y[dev] == 0]

    ae_train, ae_early = train_test_split(
        normal_dev,
        test_size=0.20,
        random_state=SEED,
    )

    ae_scaler = StandardScaler().fit(X[ae_train])

    X_ae_train = ae_scaler.transform(X[ae_train])
    X_ae_early = ae_scaler.transform(X[ae_early])
    X_ae_val = ae_scaler.transform(X[val])

    print("AE Normal training rows:", len(ae_train), flush=True)
    print("AE early-stopping rows:", len(ae_early), flush=True)

    for name, hidden, bottleneck in (
        ("AE_8x2", 8, 2),
        ("AE_12x3", 12, 3),
    ):
        print("Training:", name, flush=True)

        model = NumpyAutoencoder(
            input_dim=4,
            hidden_dim=hidden,
            bottleneck_dim=bottleneck,
            epochs=60,
            batch_size=256,
            patience=8,
            random_state=SEED,
        )

        model.fit(X_ae_train, X_ae_early)

        scores = np.asarray(
            model.anomaly_score(X_ae_val),
            dtype=float,
        ).reshape(-1)

        ap = calculate_ap(y_val, scores)

        record = {
            "name": name,
            "family": "AE",
            "validation_ap": ap,
            "epochs_executed": len(model.history_["train_loss"]),
        }
        candidates.append(record)

        if (
            "AE" not in winners
            or ap > winners["AE"][0]["validation_ap"]
        ):
            winners["AE"] = (
                record, model, ae_scaler, scores
            )

        print(f"  Validation AP: {ap:.6f}", flush=True)

    # Create new artifacts only after training succeeds.
    OUTPUT.mkdir(parents=True, exist_ok=False)

    selected = {}

    for family, (record, model, scaler, scores) in winners.items():
        model_path = OUTPUT / (
            family.lower() + "_development.joblib"
        )

        joblib.dump(
            {
                "model": model,
                "scaler": scaler,
                "features": list(FEATURES),
                "family": family,
            },
            model_path,
        )

        selected[family] = {
            "name": record["name"],
            "validation_ap": record["validation_ap"],
            "model_sha256": digest(model_path),
        }

    with (
        OUTPUT / "validation_predictions.csv"
    ).open("x", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)

        writer.writerow([
            "original_source_row",
            "true_label",
            "mlp_probability",
            "ae_anomaly_score",
        ])

        for i, label, mlp_score, ae_score in zip(
            val,
            y_val,
            winners["MLP"][3],
            winners["AE"][3],
        ):
            writer.writerow([
                int(data.source_row_indices[i]),
                int(label),
                float(mlp_score),
                float(ae_score),
            ])

    histories = {
        family: {
            key: [float(value) for value in values]
            for key, values in model.history_.items()
        }
        for family, (_, model, _, _) in winners.items()
    }

    with (
        OUTPUT / "training_history.json"
    ).open("x", encoding="utf-8") as stream:
        json.dump(histories, stream, indent=2)

    figures = save_dl_figures(
        OUTPUT / "figures",
        histories,
        y_val,
        winners["MLP"][3],
        winners["AE"][3],
    )

    summary = {
        "experiment": "unsw_dl_dev_v01",
        "stage": "DEVELOPMENT_ONLY",
        "dataset": "UNSW-NB15",
        "seed": SEED,
        "train_csv_sha256": ml.EXPECTED_TRAIN_SHA256,
        "shared_ml_split_sha256": split_sha,
        "dev_rows": len(dev),
        "validation_rows": len(val),
        "reserved_calibration_rows": len(cal),
        "reserved_calibration_used": False,
        "ae_train_normal_rows": len(ae_train),
        "ae_early_normal_rows": len(ae_early),
        "official_test_accessed": False,
        "selection_metric": "validation_average_precision",
        "candidates": candidates,
        "selected": selected,
        "figures": figures,
        "limitations": (
            "Random row split may contain correlated flows. "
            "This is development validation, not final test. "
            "No final threshold calibrated."
        ),
    }

    with (
        OUTPUT / "summary.json"
    ).open("x", encoding="utf-8") as stream:
        json.dump(summary, stream, indent=2)
        stream.write("\n")

    print("\n=== DL SELECTION ===")
    for family, info in selected.items():
        print(
            family,
            info["name"],
            f"AP={info['validation_ap']:.6f}",
        )

    print("Figures generated:", len(figures))
    print("PASS: UNSW DL DEVELOPMENT")
    print("OFFICIAL TEST NOT ACCESSED")
    print("RESERVED CALIBRATION NOT USED")


def verify():
    summary = json.loads(
        (OUTPUT / "summary.json").read_text(
            encoding="utf-8"
        )
    )

    if (
        summary.get("stage") != "DEVELOPMENT_ONLY"
        or summary.get("official_test_accessed") is not False
        or summary.get("reserved_calibration_used") is not False
    ):
        raise ValueError("Invalid DL report provenance")

    if (
        digest(ml.OUTPUT_DIR / "split_indices.npz")
        != summary["shared_ml_split_sha256"]
    ):
        raise ValueError("Shared split SHA256 mismatch")

    for family, info in summary["selected"].items():
        path = OUTPUT / (
            family.lower() + "_development.joblib"
        )

        if digest(path) != info["model_sha256"]:
            raise ValueError("Model checksum mismatch")

    for name in summary["figures"]:
        if Path(name).name != name or not name.endswith(".png"):
            raise ValueError("Invalid figure filename")

        with (
            OUTPUT / "figures" / name
        ).open("rb") as stream:
            if stream.read(8) != b"\x89PNG\r\n\x1a\n":
                raise ValueError("Invalid PNG figure")

    print("=== VERIFIED UNSW DL DEVELOPMENT ===")
    print("Selected models:", summary["selected"])
    print("Figures verified:", len(summary["figures"]))
    print("PASS: UNSW DL DEVELOPMENT VERIFIED")
    print("NO TRAINING PERFORMED")
    print("NO FILES MODIFIED")