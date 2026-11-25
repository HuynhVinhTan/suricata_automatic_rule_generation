import copy
import json
import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

from netids.experiments.unsw_v03_research_completeness import (
    DatasetUnavailable,
    METRIC_NAMES,
    preprocess_raw,
    threshold_for_budget,
    summarize_metrics,
    verify,
    write_blocked_report,
)


class TestUNSWV03ResearchCompleteness(unittest.TestCase):
    def test_missing_dataset_fails_closed(self):
        with self.assertRaises(DatasetUnavailable):
            preprocess_raw(Path("does-not-exist.csv"))

    def test_preprocessing_keeps_raw_and_removes_only_justified_rows(self):
        raw = pd.DataFrame(
            {
                "id": [1, 2, 3, 4, 5, 6],
                "dur": [1.0, 2.0, 3.0, -1.0, np.nan, 1.0],
                "proto": ["tcp", "udp", "icmp", "tcp", "tcp", "tcp"],
                "spkts": [1, 2, 1, 1, 1, np.inf],
                "dpkts": [1, 2, 1, 1, 1, 1],
                "sbytes": [10, 20, 10, 10, 10, 10],
                "dbytes": [10, 20, 10, 10, 10, 10],
                "label": [0, 1, 1, 1, 1, 1],
                "attack_cat": ["Normal", "DoS", "DoS", "DoS", "DoS", "DoS"],
            }
        )
        before = copy.deepcopy(raw)

        result = preprocess_raw(raw)

        pd.testing.assert_frame_equal(raw, before)
        self.assertEqual(result.original_rows, 6)
        self.assertEqual(result.processed_rows, 2)
        self.assertEqual(result.removed_rows, 4)
        self.assertEqual(result.processed["proto"].tolist(), ["tcp", "udp"])
        self.assertEqual(result.removal_reasons["unsupported_protocol"], 1)
        self.assertEqual(result.removal_reasons["negative_or_nonfinite_numeric"], 3)
        self.assertEqual(result.processed["label"].tolist(), [0, 1])

    def test_threshold_is_normal_only_and_respects_budget(self):
        scores = np.array([0.1, 0.2, 0.3, 0.4, 0.9])
        threshold, flagged = threshold_for_budget(scores, 0.2)

        self.assertGreaterEqual(threshold, 0.4)
        self.assertLessEqual(flagged / len(scores), 0.2)

    def test_summary_metrics_have_required_fields(self):
        values = summarize_metrics(
            np.array([0, 0, 1, 1]),
            np.array([0.1, 0.8, 0.7, 0.2]),
            threshold=0.5,
        )

        self.assertEqual(set(METRIC_NAMES), set(values))
        self.assertTrue(all(np.isfinite(list(values.values()))))

    def test_blocked_report_is_explicit_and_verifiable(self):
        with tempfile.TemporaryDirectory() as folder:
            output = write_blocked_report(Path(folder) / "v03", "test data unavailable")
            manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["status"], "BLOCKED_MISSING_DATASET")
            self.assertFalse(manifest["numbers_generated"])
            verify(output)


if __name__ == "__main__":
    unittest.main()
