
"""Unit tests for flow feature contract."""

import unittest

import numpy as np
import pandas as pd

from netids.features.schema import (
    SCHEMA_VERSION,
    FEATURE_COLUMNS,
    validate_feature_matrix,
    validate_ctu_labels,
)


class TestFeatureSchema(unittest.TestCase):

    def setUp(self):
        self.frame = pd.DataFrame({
            "protocol_tcp": [1, 0],
            "duration_log": [0.0, 1.5],
            "packets_log": [1.1, 2.3],
            "bytes_log": [4.2, 6.5],
        })

    def test_schema_version(self):
        self.assertEqual(
            SCHEMA_VERSION, "flow_features_v0.1"
        )

    def test_valid_features(self):
        result = validate_feature_matrix(self.frame)

        self.assertEqual(
            result.columns.tolist(),
            list(FEATURE_COLUMNS)
        )

    def test_column_order(self):
        reversed_frame = self.frame[
            list(reversed(FEATURE_COLUMNS))
        ]

        result = validate_feature_matrix(reversed_frame)

        self.assertEqual(
            result.columns.tolist(),
            list(FEATURE_COLUMNS)
        )

    def test_missing_feature(self):
        bad = self.frame.drop(columns="bytes_log")

        with self.assertRaises(ValueError):
            validate_feature_matrix(bad)

    def test_nan_feature(self):
        bad = self.frame.copy()
        bad.loc[0, "duration_log"] = np.nan

        with self.assertRaises(ValueError):
            validate_feature_matrix(bad)

    def test_infinite_feature(self):
        bad = self.frame.copy()
        bad.loc[0, "bytes_log"] = np.inf

        with self.assertRaises(ValueError):
            validate_feature_matrix(bad)

    def test_negative_feature(self):
        bad = self.frame.copy()
        bad.loc[0, "packets_log"] = -1

        with self.assertRaises(ValueError):
            validate_feature_matrix(bad)

    def test_invalid_protocol(self):
        bad = self.frame.copy()
        bad.loc[0, "protocol_tcp"] = 2

        with self.assertRaises(ValueError):
            validate_feature_matrix(bad)

    def test_duplicate_columns(self):
        bad = pd.concat(
            [self.frame, self.frame[["bytes_log"]]],
            axis=1
        )

        with self.assertRaises(ValueError):
            validate_feature_matrix(bad)

    def test_valid_ctu_labels(self):
        frame = pd.DataFrame({
            "label_group": [
                "Normal", "Botnet", "Background"
            ],
            "target": pd.Series(
                [0, 1, pd.NA], dtype="Int64"
            )
        })

        validate_ctu_labels(frame)

    def test_background_must_remain_unknown(self):
        bad = pd.DataFrame({
            "label_group": ["Background"],
            "target": [0]
        })

        with self.assertRaises(ValueError):
            validate_ctu_labels(bad)


if __name__ == "__main__":
    unittest.main()
