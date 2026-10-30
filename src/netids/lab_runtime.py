"""Reproducible inference for the lab SYN anomaly experiment.

Uses existing trained IsolationForest and NumPyAutoencoder.
No training, no Suricata rule deployment.
"""

import argparse
import csv
import hashlib
import json
from pathlib import Path

import joblib
import numpy as np

from netids.models.autoencoder import NumpyAutoencoder  # noqa: F401


EXPECTED_MODEL_SHA256 = (
    "206dadafc8d6cd96e21d838a52211d9b06d4a6ec541ea5c9a9ae8a6724ffbf5d"
)

DATASETS = {
    "normal-test": (
        "lab-sessions/normal-batch-v01/"
        "syn_windows_10s_normal-test.csv"
    ),
    "slow-scan-s01": (
        "lab-sessions/slow-scan-s01/"
        "syn_windows_10s_slow-scan-s01.csv"
    ),
}

LABELS = {
    "normal-test": "NORMAL",
    "slow-scan-s01": "ATTACK",
}

FEATURES = [
    "syn_count",
    "unique_dst_ports",
    "repeated_probes",
    "median_inter_syn_seconds",
    "syn_rate_per_second",
]


def sha256(path):
    h = hashlib.sha256()

    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)

    return h.hexdigest()


def load_features(path, label, seconds):
    with path.open("r", encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)

        required = set(FEATURES) | {
            "label", "window_index", "window_seconds"
        }

        if not required.issubset(reader.fieldnames or []):
            raise ValueError(f"Feature schema mismatch: {path}")

        rows = list(reader)

    if not rows:
        raise ValueError(f"Empty feature dataset: {path}")

    matrix = []
    indices = []

    for row in rows:
        if row["label"] != label:
            raise ValueError("Label mismatch")

        if int(row["window_seconds"]) != seconds:
            raise ValueError("Window length mismatch")

        count = int(row["syn_count"])
        unique = int(row["unique_dst_ports"])
        repeated = int(row["repeated_probes"])

        if count < 1 or not (1 <= unique <= count):
            raise ValueError("Invalid SYN counts")

        if repeated != count - unique:
            raise ValueError("Repeated probe feature mismatch")

        if abs(float(row["syn_rate_per_second"]) - count / seconds) > 1e-5:
            raise ValueError("SYN rate mismatch")

        indices.append(int(row["window_index"]))
        matrix.append([float(row[name]) for name in FEATURES])

    if indices != sorted(set(indices)):
        raise ValueError("Invalid window indices")

    matrix = np.asarray(matrix, dtype=np.float64)

    if not np.isfinite(matrix).all():
        raise ValueError("Non-finite input features")

    return rows, matrix


def predict(bundle, matrix):
    normalized = bundle["scaler"].transform(matrix)

    if_scores = np.asarray(
        -bundle["isolation_forest"].score_samples(normalized),
        dtype=np.float64,
    ).reshape(-1)

    ae_scores = np.asarray(
        bundle["autoencoder"].anomaly_score(normalized),
        dtype=np.float64,
    ).reshape(-1)

    if len(if_scores) != len(matrix) or len(ae_scores) != len(matrix):
        raise ValueError("Score dimension mismatch")

    if not np.isfinite(if_scores).all() or not np.isfinite(ae_scores).all():
        raise ValueError("Non-finite anomaly scores")

    thresholds = bundle["thresholds"]

    if_flags = if_scores > float(thresholds["IsolationForest"])
    ae_flags = ae_scores > float(thresholds["NumpyAutoencoder"])

    return if_scores, ae_scores, if_flags, ae_flags


def run(private_root, output):
    model_dir = (
        private_root / "lab-models" / "lab_syn_anomaly_v0_1"
    )

    model_path = model_dir / "models.joblib"
    report_path = model_dir / "report.json"

    report = json.loads(report_path.read_text(encoding="utf-8"))

    if report.get("experiment") != "lab_syn_anomaly_v0_1":
        raise ValueError("Wrong model experiment")

    if report.get("training_policy") != "NORMAL_ONLY":
        raise ValueError("Unexpected model training policy")

    if sha256(model_path) != EXPECTED_MODEL_SHA256:
        raise ValueError("Verified model SHA256 mismatch")

    # Load only this locally generated, checksum-verified artifact.
    bundle = joblib.load(model_path)

    if list(bundle["features"]) != FEATURES:
        raise ValueError("Saved model feature order mismatch")

    if list(report["feature_names"]) != FEATURES:
        raise ValueError("Report feature order mismatch")

    seconds = int(report["window_seconds"])

    if seconds != 10 or int(bundle["window_seconds"]) != seconds:
        raise ValueError("Model window contract mismatch")

    result = {
        "experiment": report["experiment"],
        "model_sha256": EXPECTED_MODEL_SHA256,
        "input_contract": "PCAP-derived SYN windows, not EVE flow",
        "window_seconds": seconds,
        "rule_deployment": False,
        "datasets": {},
    }

    for name, relative_path in DATASETS.items():
        path = private_root / relative_path

        expected_csv_hash = report["feature_csv_sha256"][name]

        if sha256(path) != expected_csv_hash:
            raise ValueError(f"Input CSV SHA256 mismatch: {name}")

        rows, matrix = load_features(
            path, LABELS[name], seconds
        )

        if_scores, ae_scores, if_flags, ae_flags = predict(
            bundle, matrix
        )

        expected_metrics = report["metrics"]

        if name == "normal-test":
            if int(if_flags.sum()) != expected_metrics[
                "IsolationForest"
            ]["normal_false_alert_windows"]:
                raise ValueError("IF Normal Test regression mismatch")

            if int(ae_flags.sum()) != expected_metrics[
                "NumpyAutoencoder"
            ]["normal_false_alert_windows"]:
                raise ValueError("AE Normal Test regression mismatch")

        else:
            for model_name, flags in (
                ("IsolationForest", if_flags),
                ("NumpyAutoencoder", ae_flags),
            ):
                expected_flags = expected_metrics[
                    model_name
                ]["attack_window_flags"]

                if flags.astype(int).tolist() != expected_flags:
                    raise ValueError(
                        f"{model_name} Attack regression mismatch"
                    )

        result["datasets"][name] = {
            "label": LABELS[name],
            "window_count": len(rows),
            "if_flagged": int(if_flags.sum()),
            "ae_flagged": int(ae_flags.sum()),
            "both_flagged": int(
                np.logical_and(if_flags, ae_flags).sum()
            ),
            "windows": [
                {
                    "window_index": int(row["window_index"]),
                    "syn_count": int(row["syn_count"]),
                    "unique_dst_ports": int(row["unique_dst_ports"]),
                    "if_score": float(if_scores[i]),
                    "ae_score": float(ae_scores[i]),
                    "if_anomaly": bool(if_flags[i]),
                    "ae_anomaly": bool(ae_flags[i]),
                }
                for i, row in enumerate(rows)
            ],
        }

        print(
            f"{name}: "
            f"windows={len(rows)}, "
            f"IF={int(if_flags.sum())}, "
            f"AE={int(ae_flags.sum())}, "
            f"both={int(np.logical_and(if_flags, ae_flags).sum())}"
        )

    if output.exists():
        raise FileExistsError("Output already exists")

    output.parent.mkdir(parents=True, exist_ok=True)

    with output.open("x", encoding="utf-8") as stream:
        json.dump(
            result,
            stream,
            ensure_ascii=False,
            indent=2,
        )

    print("PASS: INTEGRATED MODEL INFERENCE AND REGRESSION")
    print("Saved output:", output)
    print("Existing models unchanged. No rule deployed.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument(
        "--private-root",
        type=Path,
        default=Path("data/private"),
    )

    parser.add_argument(
        "--out",
        type=Path,
        required=True,
    )

    args = parser.parse_args()

    run(args.private_root, args.out)


if __name__ == "__main__":
    main()