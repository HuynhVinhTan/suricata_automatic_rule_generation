import unittest

import pandas as pd

from netids.features.splitting import (
    purged_chronological_split,
)


class TestTemporalSplit(unittest.TestCase):

    def setUp(self):
        self.frame = pd.DataFrame({
            "timestamp": pd.date_range(
                "2026-01-01",
                periods=10,
                freq="s",
            ),
            "duration_s": [
                7, 5, 0, 0, 0,
                2, 0, 0, 0, 0,
            ],
            "target": [0, 1] * 5,
        })

    def test_overlapping_flows_removed(self):
        train, test, report = purged_chronological_split(
            self.frame,
            train_fraction=0.60,
        )

        self.assertEqual(report["overlap_removed"], 2)
        self.assertEqual(report["total_removed"], 2)
        self.assertEqual(len(train), 4)
        self.assertEqual(len(test), 4)

        train_end = (
            train["timestamp"]
            + pd.to_timedelta(
                train["duration_s"],
                unit="s",
            )
        )

        self.assertTrue(
            (train_end <= test["timestamp"].min()).all()
        )

    def test_boundary_timestamp_tie_removed(self):
        frame = self.frame.copy()

        frame.loc[5, "timestamp"] = frame.loc[6, "timestamp"]
        frame.loc[5, "duration_s"] = 0
        frame.loc[0, "duration_s"] = 0
        frame.loc[1, "duration_s"] = 0

        train, test, report = purged_chronological_split(
            frame,
            train_fraction=0.60,
        )

        self.assertEqual(report["total_removed"], 1)
        self.assertTrue(
            (
                train["timestamp"]
                < test["timestamp"].min()
            ).all()
        )

    def test_original_data_not_modified(self):
        original = self.frame.copy(deep=True)

        purged_chronological_split(
            self.frame,
            train_fraction=0.60,
        )

        pd.testing.assert_frame_equal(
            self.frame,
            original,
        )

    def test_negative_duration_rejected(self):
        bad = self.frame.copy()
        bad.loc[0, "duration_s"] = -1

        with self.assertRaises(ValueError):
            purged_chronological_split(bad)


if __name__ == "__main__":
    unittest.main()