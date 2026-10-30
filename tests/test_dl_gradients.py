"""Regression test for NumPy MLP backpropagation."""

import unittest

import numpy as np

from netids.models.dl import NumpyMLP


class TestNumpyMLPGradients(unittest.TestCase):

    def test_weighted_bce_l2_gradients(self):
        model = NumpyMLP(
            input_dim=4,
            hidden1=5,
            hidden2=3,
            weight_decay=1e-4,
            random_state=42,
        )

        rng = np.random.default_rng(123)

        X = rng.normal(
            loc=0.0,
            scale=0.5,
            size=(8, 4),
        )

        y = np.array(
            [0, 1, 0, 1, 0, 1, 0, 1],
            dtype=np.float64,
        ).reshape(-1, 1)

        weights = np.where(y == 1, 2.0, 1.0)

        model._initialize(
            np.random.default_rng(42)
        )

        cache = model._forward(X)

        analytical_grads = model._backward(
            cache,
            y,
            weights,
        )

        epsilon = 1e-5

        total_parameters = 0
        max_error = 0.0

        for name, parameter in model.params_.items():

            numerical = np.zeros_like(parameter)

            for idx in np.ndindex(parameter.shape):

                original = parameter[idx]

                try:
                    parameter[idx] = original + epsilon

                    plus_cache = model._forward(X)

                    plus_loss = model._loss(
                        plus_cache["z3"],
                        y,
                        weights,
                    )

                    parameter[idx] = original - epsilon

                    minus_cache = model._forward(X)

                    minus_loss = model._loss(
                        minus_cache["z3"],
                        y,
                        weights,
                    )

                finally:
                    parameter[idx] = original

                numerical[idx] = (
                    plus_loss - minus_loss
                ) / (2 * epsilon)

            analytical = analytical_grads[name]

            error = float(np.max(
                np.abs(numerical - analytical)
            ))

            max_error = max(max_error, error)

            total_parameters += parameter.size

            np.testing.assert_allclose(
                numerical,
                analytical,
                rtol=1e-4,
                atol=1e-6,
                err_msg=f"Gradient mismatch: {name}",
            )

        self.assertEqual(total_parameters, 47)

        print(
            f"\nChecked {total_parameters} parameters."
        )

        print(
            f"Max gradient error: {max_error:.3e}"
        )


if __name__ == "__main__":
    unittest.main()
