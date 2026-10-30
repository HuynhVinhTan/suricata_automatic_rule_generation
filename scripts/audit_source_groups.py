"""Read-only, anonymized source-level review summary."""

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SOURCE = ROOT / "data/private/eve-rule-proposal-input.jsonl"
QUEUE = ROOT / "data/private/flow_review_v0_1.jsonl"
MODEL = ROOT / "artifacts/models/ctu13_rf_purged_v0_2/pipeline.joblib"

SOURCE_SHA = (
    "d4592e88a4ab2b73fc4472a5650afc4f63464527aadba2046653fbf24c5406ab"
)
MODEL_SHA = (
    "dc727edd3589666d4c8e2bd4bdbbe2a85802003db44aa5dd37cfaf8ecf44b62a"
)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main():
    if sha256(SOURCE) != SOURCE_SHA:
        raise RuntimeError("Source checksum mismatch")

    if sha256(MODEL) != MODEL_SHA:
        raise RuntimeError("Model checksum mismatch")

    with SOURCE.open(encoding="utf-8") as file:
        events = [json.loads(line) for line in file]

    with QUEUE.open(encoding="utf-8") as file:
        reviews = [json.loads(line) for line in file]

    if len(events) != 122 or len(reviews) != 122:
        raise RuntimeError("Unexpected record count")

    sources = {}
    total_flagged = 0

    for line_number, (event, review) in enumerate(
        zip(events, reviews), start=1
    ):
        proto = str(event["proto"]).upper()
        score = float(review["botnet_score"])
        predicted = int(score >= 0.5)

        if not (
            review["source_line"] == line_number
            and review["source_sha256"] == SOURCE_SHA
            and review["model_sha256"] == MODEL_SHA
            and review["protocol"] == proto
            and review["predicted_botnet"] == predicted
            and review["review_status"] == (
                "needs_review" if predicted else "not_flagged"
            )
            and review["rule_generated"] is False
        ):
            raise RuntimeError(
                f"Review mismatch at line {line_number}"
            )

        src = event["src_ip"]

        if src not in sources:
            sources[src] = {
                "total": 0,
                "flagged": 0,
                "tcp_flagged": 0,
                "udp_flagged": 0,
                "destinations": set(),
                "destination_ports": set(),
            }

        group = sources[src]
        group["total"] += 1

        if predicted:
            total_flagged += 1
            group["flagged"] += 1
            group[f"{proto.lower()}_flagged"] += 1
            group["destinations"].add(event["dest_ip"])
            group["destination_ports"].add(event["dest_port"])

    if total_flagged != 68:
        raise RuntimeError("Unexpected flagged count")

    flagged_groups = [
        group for group in sources.values()
        if group["flagged"] > 0
    ]

    flagged_groups.sort(
        key=lambda group: group["flagged"],
        reverse=True,
    )

    if len(flagged_groups) != 2:
        raise RuntimeError("Expected exactly 2 flagged sources")

    print("=== ANONYMIZED SOURCE REVIEW ===")
    print("Source SHA256: PASS")
    print("Model SHA256: PASS")
    print("Review linkage: PASS (122/122)")
    print("Total distinct source IPs:", len(sources))
    print("Source IPs with flagged flows:", len(flagged_groups))

    for index, group in enumerate(flagged_groups, start=1):
        percent = 100 * group["flagged"] / group["total"]

        print(f"\nSRC_{index:02d}")
        print("Total flows:", group["total"])
        print("Flagged flows:", group["flagged"])
        print("Flag rate: {:.1f}%".format(percent))
        print("Flagged TCP:", group["tcp_flagged"])
        print("Flagged UDP:", group["udp_flagged"])
        print(
            "Distinct destinations among flagged:",
            len(group["destinations"]),
        )
        print(
            "Distinct destination ports among flagged:",
            len(group["destination_ports"]),
        )

    print("\nPASS: SOURCE REVIEW SUMMARY COMPLETED")
    print("Actual IPs and ports not displayed.")
    print("No rules generated.")


if __name__ == "__main__":
    main()