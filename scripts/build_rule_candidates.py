"""Generate private, review-only Suricata alert candidates."""

import hashlib
import json
from collections import Counter, defaultdict
from ipaddress import ip_address
from pathlib import Path

import numpy as np
import pandas as pd

from netids.adapters.suricata import suricata_eve_to_features
from netids.features.schema import validate_feature_matrix
from netids.models.artifacts import load_ml_artifact


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "data/private/eve-rule-proposal-input.jsonl"
QUEUE = ROOT / "data/private/flow_review_v0_1.jsonl"
OUTPUT = ROOT / "data/private/rule_candidates_v0_1.json"

MODEL_DIR = ROOT / "artifacts/models/ctu13_rf_purged_v0_2"

SOURCE_SHA = (
    "d4592e88a4ab2b73fc4472a5650afc4f63464527aadba2046653fbf24c5406ab"
)
MODEL_SHA = (
    "dc727edd3589666d4c8e2bd4bdbbe2a85802003db44aa5dd37cfaf8ecf44b62a"
)

MIN_FLAGGED = 3
MIN_FLAG_RATE = 0.50
MAX_CANDIDATES = 10


def sha256(path):
    digest = hashlib.sha256()

    with path.open("rb") as file:
        for block in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(block)

    return digest.hexdigest()


def main():
    if sha256(SOURCE) != SOURCE_SHA:
        raise RuntimeError("Source SHA256 mismatch")

    if sha256(MODEL_DIR / "pipeline.joblib") != MODEL_SHA:
        raise RuntimeError("Model SHA256 mismatch")

    if OUTPUT.exists():
        raise RuntimeError("Candidate file exists; not overwriting")

    with SOURCE.open(encoding="utf-8") as file:
        events = [json.loads(line) for line in file]

    with QUEUE.open(encoding="utf-8") as file:
        reviews = [json.loads(line) for line in file]

    if len(events) != 122 or len(reviews) != 122:
        raise RuntimeError("Expected 122 records in both files")

    X = validate_feature_matrix(
        pd.DataFrame([
            suricata_eve_to_features(event)
            for event in events
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
        raise RuntimeError("Non-finite scores")

    groups = defaultdict(lambda: {
        "total": 0,
        "flagged_lines": [],
        "flagged_scores": [],
    })

    flagged_total = 0
    unsupported_ipv6 = 0

    for line_number, (event, review, score) in enumerate(
        zip(events, reviews, scores), start=1
    ):
        proto = str(event["proto"]).upper()
        flagged = int(score >= 0.5)

        if not (
            review["source_line"] == line_number
            and review["source_sha256"] == SOURCE_SHA
            and review["model_sha256"] == MODEL_SHA
            and review["protocol"] == proto
            and np.isclose(
                float(review["botnet_score"]),
                score,
                rtol=0,
                atol=1e-12,
            )
            and review["predicted_botnet"] == flagged
            and review["review_status"] == (
                "needs_review" if flagged else "not_flagged"
            )
            and review["rule_generated"] is False
        ):
            raise RuntimeError(
                f"Review linkage mismatch at line {line_number}"
            )

        flagged_total += flagged

        src = ip_address(event["src_ip"])
        dst = ip_address(event["dest_ip"])
        port = event["dest_port"]

        if type(port) is not int or not 1 <= port <= 65535:
            raise RuntimeError(
                f"Invalid destination port at line {line_number}"
            )

        # First prototype only supports IPv4 header proposals.
        if src.version != 4 or dst.version != 4:
            unsupported_ipv6 += 1
            continue

        key = (proto.lower(), str(src), str(dst), port)
        group = groups[key]
        group["total"] += 1

        if flagged:
            group["flagged_lines"].append(line_number)
            group["flagged_scores"].append(float(score))

    if flagged_total != 68:
        raise RuntimeError("Unexpected number of ML flags")

    eligible = []

    for key, group in groups.items():
        n_flagged = len(group["flagged_lines"])
        rate = n_flagged / group["total"]

        if n_flagged >= MIN_FLAGGED and rate >= MIN_FLAG_RATE:
            eligible.append((key, group))

    # Deterministic order: strongest recurrence first.
    eligible.sort(
        key=lambda item: (
            -len(item[1]["flagged_lines"]),
            -max(item[1]["flagged_scores"]),
            item[0],
        )
    )

    candidates = []
    protocol_counts = Counter()

    for index, (key, group) in enumerate(
        eligible[:MAX_CANDIDATES], start=1
    ):
        proto, src, dst, port = key

        # Provisional SID only; collisions not yet audited.
        sid = 9100000 + index

        rule_text = (
            f"alert {proto} {src} any -> {dst} {port} "
            '(msg:"ML REVIEW ONLY - NOT VERIFIED ATTACK"; '
            f"sid:{sid}; rev:1;)"
        )

        candidates.append({
            "candidate_id": f"CAND_{index:03d}",
            "status": "needs_human_review",
            "approved": False,
            "suricata_syntax_tested": False,
            "sid_uniqueness_checked": False,
            "deployable": False,
            "match_type": "header_only",
            "group_total_flows": group["total"],
            "group_flagged_flows": len(group["flagged_lines"]),
            "group_flag_rate": round(
                len(group["flagged_lines"]) / group["total"], 6
            ),
            "flagged_source_lines": group["flagged_lines"],
            "rule_text": rule_text,
        })

        protocol_counts[proto.upper()] += 1

    artifact = {
        "schema_version": "rule_candidates_v0.1",
        "source_sha256": SOURCE_SHA,
        "model_sha256": MODEL_SHA,
        "min_flagged_flows": MIN_FLAGGED,
        "min_flag_rate": MIN_FLAG_RATE,
        "warning": (
            "Unlabeled ML predictions. Header-only alert proposals. "
            "Not validated attack signatures. Do not deploy."
        ),
        "candidates": candidates,
    }

    # Keep actual IPs/ports inside Git-ignored data/private.
    with OUTPUT.open("x", encoding="utf-8") as file:
        json.dump(artifact, file, indent=2)
        file.write("\n")

    print("=== PRIVATE SURICATA RULE CANDIDATES ===")
    print("Source SHA256: PASS")
    print("Model SHA256: PASS")
    print("Review linkage: PASS (122/122)")
    print("ML-flagged flows:", flagged_total)
    print("Groups meeting review criteria:", len(eligible))
    print("Draft candidates created:", len(candidates))
    print("TCP draft candidates:", protocol_counts["TCP"])
    print("UDP draft candidates:", protocol_counts["UDP"])
    print("IPv6 records skipped for candidate grouping:",
          unsupported_ipv6)
    print("Private output:", OUTPUT.relative_to(ROOT))
    print("No IP or port values displayed.")
    print("No .rules file generated or deployed.")


if __name__ == "__main__":
    main()