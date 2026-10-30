"""Build a private, non-deployable ML flow review queue."""

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

INPUT = ROOT / "data/private/eve-rule-proposal-input.jsonl"
OUTPUT = ROOT / "data/private/flow_review_v0_1.jsonl"

MODEL_DIR = ROOT / "artifacts/models/ctu13_rf_purged_v0_2"

INPUT_SHA256 = (
    "d4592e88a4ab2b73fc4472a5650afc4f63464527aadba2046653fbf24c5406ab"
)

MODEL_SHA256 = (
    "dc727edd3589666d4c8e2bd4bdbbe2a85802003db44aa5dd37cfaf8ecf44b62a"
)

THRESHOLD = 0.5


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    if sha256(INPUT) != INPUT_SHA256:
        raise RuntimeError("Input SHA256 mismatch")

    if sha256(MODEL_DIR / "pipeline.joblib") != MODEL_SHA256:
        raise RuntimeError("Model SHA256 mismatch")

    if OUTPUT.exists():
        raise RuntimeError("Review file already exists; not overwriting")

    features = []
    protocols = []

    with INPUT.open("r", encoding="utf-8") as file:
        lines = file.readlines()

    if len(lines) != 122:
        raise RuntimeError("Unexpected input record count")

    for line_number, line in enumerate(lines, start=1):
        try:
            event = json.loads(line)

            if event.get("event_type") != "flow":
                raise ValueError("Not a flow")

            proto = str(event["proto"]).upper()

            if proto not in {"TCP", "UDP"}:
                raise ValueError("Unsupported protocol")

            # Verify that this exact event retains its 5-tuple.
            required = (
                "src_ip", "dest_ip",
                "src_port", "dest_port",
            )

            if any(event.get(key) is None for key in required):
                raise ValueError("Missing connection metadata")

            feature = suricata_eve_to_features(event)

        except (ValueError, TypeError, KeyError, OverflowError):
            raise RuntimeError(
                f"Invalid input at line {line_number}"
            ) from None

        features.append(feature)
        protocols.append(proto)

    X = validate_feature_matrix(pd.DataFrame(features))

    model, metadata = load_ml_artifact(MODEL_DIR)

    if metadata["schema_version"] != "flow_features_v0.1":
        raise RuntimeError("Feature schema mismatch")

    classes = list(model.classes_)

    if set(classes) != {0, 1}:
        raise RuntimeError("Unexpected model classes")

    positive_index = classes.index(1)
    scores = model.predict_proba(X)[:, positive_index]

    if not np.isfinite(scores).all():
        raise RuntimeError("Non-finite model scores")

    counts = Counter()
    flagged = Counter()
    review_rows = []

    for line_number, (proto, score) in enumerate(
        zip(protocols, scores), start=1
    ):
        predicted = int(score >= THRESHOLD)

        counts[proto] += 1
        flagged[proto] += predicted

        review_rows.append({
            "source_line": line_number,
            "source_sha256": INPUT_SHA256,
            "model_sha256": MODEL_SHA256,
            "protocol": proto,
            "botnet_score": float(score),
            "predicted_botnet": predicted,
            "review_status": (
                "needs_review" if predicted else "not_flagged"
            ),
            "rule_generated": False,
        })

    # Regression check against the already observed CLI results.
    if (
        counts["TCP"] != 36
        or counts["UDP"] != 86
        or flagged["TCP"] != 12
        or flagged["UDP"] != 56
    ):
        raise RuntimeError("Results differ from verified CLI run")

    # Exclusive creation: never overwrite an existing review file.
    with OUTPUT.open("x", encoding="utf-8") as file:
        for row in review_rows:
            file.write(json.dumps(row) + "\n")

    print("=== ML FLOW REVIEW QUEUE ===")
    print("Input SHA256: PASS")
    print("Model SHA256: PASS")
    print("Records linked:", len(review_rows))
    print(f"TCP needs review: {flagged['TCP']}/{counts['TCP']}")
    print(f"UDP needs review: {flagged['UDP']}/{counts['UDP']}")
    print("Total needs review:", sum(flagged.values()))
    print("Review file:", OUTPUT.relative_to(ROOT))
    print("No IP or port values copied into review file.")
    print("No Suricata rules generated.")


if __name__ == "__main__":
    main()