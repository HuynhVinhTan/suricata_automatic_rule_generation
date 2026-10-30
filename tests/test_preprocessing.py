
import unittest

import numpy as np
import pandas as pd

from sklearn.exceptions import NotFittedError

from netids.features.schema import FEATURE_COLUMNS
from netids.features.preprocessing import (
    FeatureContractTransformer,
)
from netids.models.ml import make_ml_pipeline


class TestMLPipelines(unittest.TestCase):

    def setUp(self):
        self.X = pd.DataFrame({
            "protocol_tcp": [0, 1, 0, 1, 0, 1, 0, 1],
            "duration_log": [
                0.2, 2.0, 0.3, 3.1,
                0.4, 2.8, 0.5, 3.3
            ],
            "packets_log": [1, 3, 1, 2, 2, 4, 1, 4],
            "bytes_log": [2, 6, 2, 5, 3, 7, 2, 8],
        })

        self.y = np.array([0, 1, 0, 1, 0, 1, 0, 1])

    def test_transformer_requires_fit(self):
        transformer = FeatureContractTransformer()

        with self.assertRaises(NotFittedError):
            transformer.transform(self.X)

    def test_feature_order_and_metadata_exclusion(self):
        model = make_ml_pipeline("random_forest")
        model.fit(self.X, self.y)

        extra = self.X.loc[
            :, list(reversed(FEATURE_COLUMNS))
        ].copy()

        extra["target"] = 999

        np.testing.assert_array_equal(
            model.predict(self.X),
            model.predict(extra)
        )

    def test_scaler_fit_only_on_training(self):
        model = make_ml_pipeline("logistic_regression")
        model.fit(self.X, self.y)

        expected_mean = self.X.loc[
            :, list(FEATURE_COLUMNS)
        ].mean().to_numpy()

        np.testing.assert_allclose(
            model.named_steps["scaler"].mean_,
            expected_mean
        )

        test_x = self.X.iloc[[0]].copy()
        test_x["bytes_log"] = 1000.0

        model.predict(test_x)

        np.testing.assert_allclose(
            model.named_steps["scaler"].mean_,
            expected_mean
        )

    def test_missing_feature_rejected_at_prediction(self):
        model = make_ml_pipeline("random_forest")
        model.fit(self.X, self.y)

        with self.assertRaises(ValueError):
            model.predict(
                self.X.drop(columns=["bytes_log"])
            )

    def test_unknown_model_rejected(self):
        with self.assertRaises(ValueError):
            make_ml_pipeline("unsupported")


if __name__ == "__main__":
    unittest.main()
