"""Offline Suricata EVE batch inference. No alerts or rules."""

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd

from netids.adapters.suricata import suricata_eve_to_features
from netids.features.schema import validate_feature_matrix
from netids.models.artifacts import load_ml_artifact


ROOT = Path(__file__).resolve().parents[1]

MODEL_DIR = (
    ROOT / "artifacts" / "models" / "ctu13_rf_purged_v0_2"
)

MODEL_SHA256 = (
    "dc727edd3589666d4c8e2bd4bdbbe2a85802003db44aa5dd37cfaf8ecf44b62a"
)

THRESHOLD = 0.5


def sha256(path):
    digest = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(
            lambda: file.read(1024 * 1024), b""
        ):
            digest.update(chunk)

    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--input",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--expected-sha256",
        required=True,
    )

    args = parser.parse_args()

    print("=== EVE BATCH CLI DRY-RUN ===")

    if sha256(args.input) != args.expected_sha256.lower():
        raise RuntimeError("Input SHA256 mismatch")

    print("Input SHA256: PASS")

    model_path = MODEL_DIR / "pipeline.joblib"

    if sha256(model_path) != MODEL_SHA256:
        raise RuntimeError("Model SHA256 mismatch")

    print("Model SHA256: PASS")

    features = []
    protocols = []
    rejected = Counter()
    total = 0

    with args.input.open("r", encoding="utf-8") as file:
        for line in file:
            total += 1

            try:
                event = json.loads(line)
                feature = suricata_eve_to_features(event)

            except (
                ValueError,
                TypeError,
                KeyError,
                OverflowError,
            ) as exc:
                rejected[type(exc).__name__] += 1
                continue

            features.append(feature)
            protocols.append(
                str(event["proto"]).strip().upper()
            )

    if not features:
        raise RuntimeError("No valid EVE flows")

    X = validate_feature_matrix(
        pd.DataFrame(features)
    )

    model, metadata = load_ml_artifact(MODEL_DIR)

    if metadata["schema_version"] != "flow_features_v0.1":
        raise RuntimeError("Feature schema mismatch")

    classes = list(model.classes_)

    if set(classes) != {0, 1}:
        raise RuntimeError("Unexpected model classes")

    positive_index = classes.index(1)

    scores = model.predict_proba(X)[:, positive_index]

    if not np.isfinite(scores).all():
        raise RuntimeError("Non-finite prediction scores")

    results = pd.DataFrame({
        "protocol": protocols,
        "botnet_score": scores,
        "predicted_botnet": (
            scores >= THRESHOLD
        ).astype(int),
    })

    summary = (
        results.groupby("protocol")
        .agg(
            valid_flows=("botnet_score", "size"),
            predicted_botnet=("predicted_botnet", "sum"),
            median_score=("botnet_score", "median"),
            min_score=("botnet_score", "min"),
            max_score=("botnet_score", "max"),
        )
    )

    print("\nTotal records:", total)
    print("Valid flows:", len(results))
    print("Rejected flows:", sum(rejected.values()))
    print("Rejection reasons:", dict(rejected))

    print("\n=== RESULTS BY PROTOCOL ===")
    print(summary.round(6).to_string())

    print("\nPASS: EVE BATCH CLI DRY-RUN COMPLETED")
    print("No model training.")
    print("No alerts or Suricata rules generated.")


if __name__ == "__main__":
    main()