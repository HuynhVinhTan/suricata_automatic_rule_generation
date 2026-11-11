"""Record isolated Suricata Attack/Normal replay evidence for a rule run."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from netids.rulegen import apply_replay_validation


def count_sid_alerts(eve_path: Path, sid: int) -> int:
    count = 0
    with eve_path.open(encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            event = json.loads(line)
            alert = event.get("alert")
            if event.get("event_type") == "alert" and isinstance(alert, dict) and alert.get("signature_id") == sid:
                count += 1
    return count


def validate_rule_replay(*, output_dir: Path, attack_eve: Path, normal_eve: Path, sid: int) -> dict:
    attack_alerts = count_sid_alerts(attack_eve, sid)
    normal_alerts = count_sid_alerts(normal_eve, sid)
    metadata = apply_replay_validation(
        output_dir,
        attack_alerts=attack_alerts,
        normal_alerts=normal_alerts,
    )
    review_path = output_dir / "review.json"
    review = json.loads(review_path.read_text(encoding="utf-8"))
    review["status"] = metadata["status"]
    review["generation_rejection"] = metadata["rejection_reason"]
    review["normal_replay_tested_in_this_run"] = True
    review["attack_replay_alerts"] = attack_alerts
    review["normal_replay_alerts"] = normal_alerts
    review["approved"] = False
    review["deployable"] = False
    review["deployed"] = False
    review_path.write_text(
        json.dumps(review, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return {
        "status": metadata["status"],
        "rejection_reason": metadata["rejection_reason"],
        "attack_replay_alerts": attack_alerts,
        "normal_replay_alerts": normal_alerts,
        "rule_sha256": metadata["rule_sha256"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--attack-eve", type=Path, required=True)
    parser.add_argument("--normal-eve", type=Path, required=True)
    parser.add_argument("--sid", type=int, required=True)
    args = parser.parse_args(argv)
    print(json.dumps(validate_rule_replay(
        output_dir=args.output_dir,
        attack_eve=args.attack_eve,
        normal_eve=args.normal_eve,
        sid=args.sid,
    ), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
