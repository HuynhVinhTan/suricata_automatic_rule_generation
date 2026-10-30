"""Regression tests for the v02 canonical CLI dispatch."""

import unittest
from unittest.mock import patch

from netids.experiments.run import dispatch


class TestV02Dispatch(unittest.TestCase):

    def test_v02_routes_develop(self):
        with patch(
            "netids.experiments.unsw_v02_development.run"
        ) as train:
            dispatch(
                "unsw-nb15",
                "develop",
                "all",
                "v02",
            )
            train.assert_called_once_with()

    def test_v02_routes_report(self):
        with patch(
            "netids.experiments.unsw_v02_official_test.verify"
        ) as report:
            dispatch(
                "unsw-nb15",
                "report",
                "all",
                "v02",
            )
            report.assert_called_once_with()

    def test_v02_rejects_incompatible_family(self):
        with patch(
            "netids.experiments.unsw_v02_development.run"
        ) as train:
            with self.assertRaises(ValueError):
                dispatch(
                    "unsw-nb15",
                    "develop",
                    "ml",
                    "v02",
                )
            train.assert_not_called()

    def test_v02_routes_test_stage(self):
        with patch(
            "netids.experiments.unsw_v02_official_test.run"
        ) as official_run, patch(
            "netids.experiments.unsw_v02_official_test.verify"
        ) as official_verify:
            dispatch(
                "unsw-nb15",
                "test",
                "all",
                "v02",
            )
            official_run.assert_called_once_with()
            official_verify.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()