import unittest

import numpy as np

from netids.models.autoencoder import NumpyAutoencoder


class TestNumpyAutoencoder(unittest.TestCase):

    def test_training_and_scoring(self):
        rng = np.random.default_rng(42)

        X = rng.normal(size=(140, 4))

        train = X[:100]
        calibration = X[100:]

        model = NumpyAutoencoder(
            epochs=40,
            patience=10,
            random_state=4,
        )

        model.fit(train, calibration)

        scores = model.anomaly_score(calibration)

        self.assertEqual(scores.shape, (40,))
        self.assertTrue(np.isfinite(scores).all())
        self.assertTrue(np.all(scores >= 0))

        self.assertTrue(
            np.isfinite(model.best_cal_loss_)
        )

        self.assertTrue(
            1 <= model.best_epoch_
            <= model.epochs_ran_
            <= 40
        )

    def test_gradient(self):
        model = NumpyAutoencoder(
            hidden_dim=3,
            bottleneck_dim=2,
            weight_decay=0.001,
        )

        model._initialize(
            np.random.default_rng(42)
        )

        X = np.random.default_rng(3).normal(
            size=(6, 4)
        )

        cache = model._forward(X)
        grads = model._backward(cache)

        epsilon = 1e-5

        for name, parameter in model.params_.items():
            for idx in np.ndindex(parameter.shape):
                original = parameter[idx]

                try:
                    parameter[idx] = original + epsilon

                    plus = model._loss(
                        model._forward(X)
                    )

                    parameter[idx] = original - epsilon

                    minus = model._loss(
                        model._forward(X)
                    )

                finally:
                    parameter[idx] = original

                numerical = (
                    plus - minus
                ) / (2 * epsilon)

                self.assertAlmostEqual(
                    numerical,
                    grads[name][idx],
                    places=6,
                )

    def test_unfitted_model(self):
        model = NumpyAutoencoder()

        X = np.ones((2, 4))

        with self.assertRaises(RuntimeError):
            model.anomaly_score(X)


if __name__ == "__main__":
    unittest.main()