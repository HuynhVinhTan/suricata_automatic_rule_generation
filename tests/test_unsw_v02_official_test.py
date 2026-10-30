"""Unit tests for frozen official-test metrics."""

import unittest

from netids.experiments.unsw_v02_official_test import (
    metrics,
)


class TestOfficialTestMetrics(unittest.TestCase):

    def test_confusion_matrix_and_rates(self):
        result = metrics(
            [0, 0, 1, 1],
            [0.1, 0.8, 0.6, 0.9],
            0.7,
        )

        self.assertEqual(
            (
                result["tn"],
                result["fp"],
                result["fn"],
                result["tp"],
            ),
            (1, 1, 1, 1),
        )

        self.assertAlmostEqual(result["fpr"], 0.5)
        self.assertAlmostEqual(result["recall"], 0.5)

    def test_refuses_invalid_labels(self):
        with self.assertRaises(ValueError):
            metrics([0, 2], [0.1, 0.9], 0.5)


if __name__ == "__main__":
    unittest.main()