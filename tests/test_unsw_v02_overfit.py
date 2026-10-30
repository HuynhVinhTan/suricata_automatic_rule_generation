"""Read-only overfitting metric contract tests."""

import unittest
from unittest.mock import patch

from netids.evaluation.unsw_v02_overfit import measures
from netids.experiments.run import dispatch


class TestOverfittingAudit(unittest.TestCase):

    def test_metric_contract(self):
        result = measures(
            [0, 0, 1, 1],
            [0.1, 0.8, 0.7, 0.9],
            0.75,
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

    def test_cli_routes_to_audit(self):
        with patch(
            "netids.evaluation.unsw_v02_overfit.run"
        ) as audit:
            dispatch(
                "unsw-nb15",
                "audit",
                "all",
                "v02",
            )
            audit.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()