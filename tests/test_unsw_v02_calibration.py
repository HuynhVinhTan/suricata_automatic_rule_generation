"""Calibration safety tests for the canonical v02 pipeline."""

import unittest
import numpy as np

from netids.experiments.unsw_v02_calibration import (
    threshold_for_budget,
)


class TestV02Calibration(unittest.TestCase):

    def test_budget_with_distinct_values(self):
        threshold, fp = threshold_for_budget(
            [0.1, 0.2, 0.3, 0.9],
            0.25,
        )

        self.assertEqual(fp, 1)
        self.assertGreater(threshold, 0.3)

    def test_ties_cannot_exceed_budget(self):
        threshold, fp = threshold_for_budget(
            [0.2, 0.2, 0.2, 0.2],
            0.25,
        )

        self.assertEqual(fp, 0)
        self.assertGreater(threshold, 0.2)

    def test_zero_budget(self):
        threshold, fp = threshold_for_budget(
            [0.1, 0.4, 0.9],
            0.0,
        )

        self.assertEqual(fp, 0)
        self.assertGreater(threshold, 0.9)

    def test_reject_invalid_inputs(self):
        for values, budget in (
            ([], 0.01),
            ([np.nan], 0.01),
            ([0.1], 1.0),
            ([0.1], -0.1),
        ):
            with self.subTest(
                values=values, budget=budget
            ):
                with self.assertRaises(ValueError):
                    threshold_for_budget(values, budget)


if __name__ == "__main__":
    unittest.main()