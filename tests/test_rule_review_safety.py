import csv
import hashlib
import json
import unittest
from pathlib import Path

from netids.rulegen import build_syn_burst_review_rule


ROOT = Path(__file__).resolve().parents[1]
PRIVATE = ROOT / "data" / "private"


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class RuleReviewSafetyTests(unittest.TestCase):

    def test_normal_reference_and_known_failed_candidate(self):
        model_report_path = (
            PRIVATE / "lab-models"
            / "lab_syn_anomaly_v0_1" / "report.json"
        )
        old_dir = (
            PRIVATE / "lab-rule-candidates" / "syn_scan_v0_1"
        )
        required_private_files = (
            model_report_path,
            old_dir / "proposal.json",
            PRIVATE / "lab-sessions" / "normal-batch-v01"
            / "syn_windows_10s_normal-train.csv",
            PRIVATE / "lab-sessions" / "normal-batch-v01"
            / "syn_windows_10s_normal-cal.csv",
            old_dir / "candidate.rules",
        )
        missing = [str(path.relative_to(ROOT)) for path in required_private_files if not path.is_file()]
        if missing:
            self.skipTest(
                "Owner-held private lab evidence is unavailable in this checkout: "
                + ", ".join(missing)
            )

        report = json.loads(
            model_report_path.read_text(encoding="utf-8")
        )
        old_proposal = json.loads(
            (old_dir / "proposal.json").read_text(
                encoding="utf-8-sig"
            )
        )

        self.assertEqual(
            old_proposal["model_report_sha256"],
            sha256(model_report_path),
        )
        self.assertEqual(old_proposal["status"], "needs_review")
        self.assertIs(old_proposal["deployed"], False)

        normal_counts = []

        for partition in ("normal-train", "normal-cal"):
            path = (
                PRIVATE / "lab-sessions" / "normal-batch-v01"
                / f"syn_windows_10s_{partition}.csv"
            )

            self.assertEqual(
                sha256(path),
                report["feature_csv_sha256"][partition],
            )

            with path.open(
                encoding="utf-8", newline=""
            ) as stream:
                rows = list(csv.DictReader(stream))

            self.assertTrue(rows)

            for row in rows:
                self.assertEqual(row["label"], "NORMAL")
                self.assertEqual(int(row["window_seconds"]), 10)
                count = int(row["syn_count"])
                self.assertGreaterEqual(count, 1)
                normal_counts.append(count)

        generated = build_syn_burst_review_rule(
            destination_ip="192.168.10.10",
            normal_max_syn=max(normal_counts),
        )
        previously_failed = (
            old_dir / "candidate.rules"
        ).read_text(encoding="utf-8").strip()

        self.assertEqual(generated, previously_failed)
        self.assertIn("sid:9102001;", generated)
        print(
            "Verified Normal-only threshold:",
            max(3, max(normal_counts) + 1),
        )
        print("Known false-positive candidate: EXACT MATCH")

    def test_normal_threshold_contract(self):
        for normal_max, expected in (
            (0, 3), (2, 3), (4, 5)
        ):
            with self.subTest(normal_max=normal_max):
                rule = build_syn_burst_review_rule(
                    destination_ip="192.168.10.10",
                    normal_max_syn=normal_max,
                )
                self.assertIn(
                    f"count {expected},seconds 10;",
                    rule,
                )
                self.assertIn(
                    "LAB AI REVIEW SYN burst proxy", rule
                )
                self.assertIn("sid:9102001;", rule)

    def test_invalid_inputs_are_rejected(self):
        cases = (
            {"destination_ip": "::1"},
            {"destination_ip": "invalid-ip"},
            {"normal_max_syn": -1},
            {"normal_max_syn": 1.5},
            {"window_seconds": 5},
            {"sid": 0},
            {"sid": True},
        )

        for override in cases:
            with self.subTest(override=override):
                arguments = {
                    "destination_ip": "192.168.10.10",
                    "normal_max_syn": 2,
                }
                arguments.update(override)

                with self.assertRaises(ValueError):
                    build_syn_burst_review_rule(**arguments)


if __name__ == "__main__":
    unittest.main()
