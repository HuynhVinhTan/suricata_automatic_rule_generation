"""Audit ML review queue without exposing network identities."""

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

SOURCE = ROOT / "data/private/eve-rule-proposal-input.jsonl"
QUEUE = ROOT / "data/private/flow_review_v0_1.jsonl"
MODEL_DIR = ROOT / "artifacts/models/ctu13_rf_purged_v0_2"

SOURCE_SHA = (
    "d4592e88a4ab2b73fc4472a5650afc4f63464527aadba2046653fbf24c5406ab"
)
MODEL_SHA = (
    "dc727edd3589666d4c8e2bd4bdbbe2a85802003db44aa5dd37cfaf8ecf44b62a"
)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    if sha256(SOURCE) != SOURCE_SHA:
        raise RuntimeError("Source checksum mismatch")

    if sha256(MODEL_DIR / "pipeline.joblib") != MODEL_SHA:
        raise RuntimeError("Model checksum mismatch")

    source_rows = [
        json.loads(line)
        for line in SOURCE.read_text(encoding="utf-8").splitlines()
    ]

    review_rows = [
        json.loads(line)
        for line in QUEUE.read_text(encoding="utf-8").splitlines()
    ]

    if len(source_rows) != 122 or len(review_rows) != 122:
        raise RuntimeError("Expected 122 records in both files")

    X = validate_feature_matrix(
        pd.DataFrame([
            suricata_eve_to_features(event)
            for event in source_rows
        ])
    )

    model, metadata = load_ml_artifact(MODEL_DIR)

    if metadata["schema_version"] != "flow_features_v0.1":
        raise RuntimeError("Feature schema mismatch")

    classes = list(model.classes_)

    if set(classes) != {0, 1}:
        raise RuntimeError("Unexpected model classes")

    scores = model.predict_proba(X)[:, classes.index(1)]

    if not np.isfinite(scores).all():
        raise RuntimeError("Invalid model scores")

    flagged_sources = Counter()
    flagged_protocols = Counter()
    candidates = []

    for line_number, (event, review, score) in enumerate(
        zip(source_rows, review_rows, scores), start=1
    ):
        predicted = int(score >= 0.5)
        proto = str(event["proto"]).upper()

        if (
            review["source_line"] != line_number
            or review["source_sha256"] != SOURCE_SHA
            or review["model_sha256"] != MODEL_SHA
            or review["protocol"] != proto
            or abs(float(review["botnet_score"]) - float(score)) > 1e-12
            or review["predicted_botnet"] != predicted
            or review["review_status"]
            != ("needs_review" if predicted else "not_flagged")
            or review["rule_generated"] is not False
        ):
            raise RuntimeError(
                f"Review linkage mismatch at line {line_number}"
            )

        if predicted:
            # Only count IPs in memory; never print their values.
            flagged_sources[event["src_ip"]] += 1
            flagged_protocols[proto] += 1

            flow = event["flow"]

            packets = (
                flow["pkts_toserver"] + flow["pkts_toclient"]
            )
            bytes_total = (
                flow["bytes_toserver"] + flow["bytes_toclient"]
            )

            candidates.append({
                "line": line_number,
                "protocol": proto,
                "score": float(score),
                "packets": packets,
                "bytes": bytes_total,
            })

    candidates.sort(key=lambda row: (-row["score"], row["line"]))

    print("=== PRIVATE REVIEW EVIDENCE AUDIT ===")
    print("Input checksum: PASS")
    print("Model checksum: PASS")
    print("Review linkage: PASS (122/122)")

    print("TCP flagged:", flagged_protocols["TCP"])
    print("UDP flagged:", flagged_protocols["UDP"])
    print("Total flagged:", len(candidates))

    print("Distinct source IPs among flagged flows:",
          len(flagged_sources))

    print("Source IPs with >=3 flagged flows:",
          sum(n >= 3 for n in flagged_sources.values()))

    print("\n=== TOP 5 FLAGGED FLOWS (REDACTED) ===")

    for candidate in candidates[:5]:
        print(
            f"line={candidate['line']} "
            f"protocol={candidate['protocol']} "
            f"score={candidate['score']:.6f} "
            f"packets={candidate['packets']} "
            f"bytes={candidate['bytes']}"
        )

    print("\nPASS: REVIEW EVIDENCE AUDIT COMPLETED")
    print("No IP or port values displayed.")
    print("No rules generated.")


if __name__ == "__main__":
    main()