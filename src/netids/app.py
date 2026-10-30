"""Inference CLI for 10-second PCAP-derived SYN windows; no training/deploy."""

import argparse
import csv
import json
from pathlib import Path

import joblib
import numpy as np

from netids.lab_runtime import (
    EXPECTED_MODEL_SHA256,
    FEATURES,
    predict,
    sha256,
)


def read_windows(path, seconds):
    with path.open("r", encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        required = set(FEATURES) | {"window_index", "window_seconds"}

        if not required.issubset(reader.fieldnames or []):
            raise ValueError("Invalid SYN-window CSV schema")

        rows = list(reader)

    if not rows:
        raise ValueError("Empty SYN-window CSV")

    values = []
    indices = []

    for row in rows:
        if int(row["window_seconds"]) != seconds:
            raise ValueError("Window size does not match model")

        index = int(row["window_index"])
        count = int(row["syn_count"])
        unique = int(row["unique_dst_ports"])
        repeated = int(row["repeated_probes"])

        if index < 0 or count < 1 or not 1 <= unique <= count:
            raise ValueError("Invalid window index or SYN counts")

        if repeated != count - unique:
            raise ValueError("Invalid repeated_probes")

        if abs(float(row["syn_rate_per_second"]) - count / seconds) > 1e-5:
            raise ValueError("Invalid syn_rate_per_second")

        sample = [float(row[name]) for name in FEATURES]

        if sample[3] < 0:
            raise ValueError("Negative SYN interarrival time")

        values.append(sample)
        indices.append(index)

    if indices != sorted(set(indices)):
        raise ValueError("Duplicate or unordered window indices")

    matrix = np.asarray(values, dtype=np.float64)

    if not np.isfinite(matrix).all():
        raise ValueError("Non-finite features")

    return rows, matrix


def run(private_root, input_csv, expected_input_sha256, output):
    if output.exists():
        raise FileExistsError("Output exists; refusing overwrite")

    if not output.resolve().is_relative_to(private_root.resolve()):
        raise ValueError("Output must be under private data root")

    model_dir = private_root / "lab-models" / "lab_syn_anomaly_v0_1"
    model_path = model_dir / "models.joblib"
    report_path = model_dir / "report.json"

    report = json.loads(report_path.read_text(encoding="utf-8"))

    if (
        report.get("experiment") != "lab_syn_anomaly_v0_1"
        or report.get("training_policy") != "NORMAL_ONLY"
        or list(report.get("feature_names", [])) != FEATURES
        or int(report.get("window_seconds", -1)) != 10
    ):
        raise ValueError("Unexpected model report or feature contract")

    if sha256(model_path) != EXPECTED_MODEL_SHA256:
        raise ValueError("Model SHA256 mismatch")

    input_hash = sha256(input_csv)

    if input_hash != expected_input_sha256.lower():
        raise ValueError("Input SHA256 mismatch")

    # Load only the previously trained and checksum-verified model.
    bundle = joblib.load(model_path)

    if (
        list(bundle["features"]) != FEATURES
        or int(bundle["window_seconds"]) != 10
    ):
        raise ValueError("Saved model schema mismatch")

    for name in ("IsolationForest", "NumpyAutoencoder"):
        if not np.isclose(
            float(bundle["thresholds"][name]),
            float(report["thresholds"][name]),
            rtol=0,
            atol=1e-12,
        ):
            raise ValueError("Saved anomaly threshold mismatch")

    rows, matrix = read_windows(input_csv, 10)

    if_scores, ae_scores, if_flags, ae_flags = predict(bundle, matrix)
    both = np.logical_and(if_flags, ae_flags)

    result = {
        "schema_version": "lab_syn_inference_v0_1",
        "input_contract": "10s PCAP-derived SYN windows; NOT EVE flows",
        "input_sha256": input_hash,
        "model_sha256": EXPECTED_MODEL_SHA256,
        "training_performed": False,
        "suricata_rule_generated": False,
        "rule_deployed": False,
        "windows": len(rows),
        "isolation_forest_flagged": int(if_flags.sum()),
        "autoencoder_flagged": int(ae_flags.sum()),
        "both_flagged": int(both.sum()),
        "predictions": [
            {
                "window_index": int(row["window_index"]),
                "syn_count": int(row["syn_count"]),
                "unique_dst_ports": int(row["unique_dst_ports"]),
                "if_score": float(if_scores[i]),
                "ae_score": float(ae_scores[i]),
                "if_anomaly": bool(if_flags[i]),
                "ae_anomaly": bool(ae_flags[i]),
                "both_anomaly": bool(both[i]),
            }
            for i, row in enumerate(rows)
        ],
    }

    output.parent.mkdir(parents=True, exist_ok=True)

    with output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, ensure_ascii=False)
        stream.write("\n")

    print(
        f"Windows: {len(rows)} | IF: {int(if_flags.sum())} | "
        f"AE: {int(ae_flags.sum())} | both: {int(both.sum())}"
    )

    print("Output:", output)
    print("PASS: GENERIC SYN-WINDOW INFERENCE")


def main():
    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument(
        "--private-root", type=Path, default=Path("data/private")
    )
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--input-sha256", required=True)
    parser.add_argument("--out", type=Path, required=True)

    args = parser.parse_args()

    run(
        args.private_root,
        args.input,
        args.input_sha256,
        args.out,
    )


if __name__ == "__main__":
    main()