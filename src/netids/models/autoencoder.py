"""NumPy autoencoder for experimental flow anomaly detection."""

import numpy as np


class NumpyAutoencoder:
    """Fully connected autoencoder: 4 -> 8 -> 2 -> 8 -> 4."""

    def __init__(
        self,
        input_dim=4,
        hidden_dim=8,
        bottleneck_dim=2,
        learning_rate=0.002,
        weight_decay=1e-4,
        epochs=150,
        batch_size=64,
        patience=20,
        random_state=42,
    ):
        if min(
            input_dim, hidden_dim, bottleneck_dim,
            epochs, batch_size, patience
        ) < 1:
            raise ValueError("Invalid architecture or training settings.")

        if learning_rate <= 0 or weight_decay < 0:
            raise ValueError("Invalid optimizer parameters.")

        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.bottleneck_dim = bottleneck_dim
        self.learning_rate = learning_rate
        self.weight_decay = weight_decay
        self.epochs = epochs
        self.batch_size = batch_size
        self.patience = patience
        self.random_state = random_state

    def _check_X(self, X):
        X = np.asarray(X, dtype=np.float64)

        if (
            X.ndim != 2
            or len(X) == 0
            or X.shape[1] != self.input_dim
            or not np.isfinite(X).all()
        ):
            raise ValueError(
                f"Expected finite 2-D data with "
                f"{self.input_dim} features."
            )

        return X

    def _initialize(self, rng):
        dims = (
            self.input_dim,
            self.hidden_dim,
            self.bottleneck_dim,
            self.hidden_dim,
            self.input_dim,
        )

        self.params_ = {}

        for i in range(1, 5):
            self.params_[f"W{i}"] = rng.normal(
                loc=0.0,
                scale=np.sqrt(
                    2.0 / (dims[i - 1] + dims[i])
                ),
                size=(dims[i - 1], dims[i]),
            )

            self.params_[f"b{i}"] = np.zeros(
                (1, dims[i])
            )

    def _forward(self, X):
        p = self.params_

        a1 = np.tanh(
            X @ p["W1"] + p["b1"]
        )

        a2 = np.tanh(
            a1 @ p["W2"] + p["b2"]
        )

        a3 = np.tanh(
            a2 @ p["W3"] + p["b3"]
        )

        output = (
            a3 @ p["W4"] + p["b4"]
        )

        return X, a1, a2, a3, output

    def _loss(self, cache):
        X, _, _, _, output = cache

        mse = np.mean(
            (output - X) ** 2
        )

        regularization = (
            0.5 * self.weight_decay
            * sum(
                np.sum(
                    self.params_[f"W{i}"] ** 2
                )
                for i in range(1, 5)
            )
        )

        return float(mse + regularization)

    def _backward(self, cache):
        X, a1, a2, a3, output = cache
        p = self.params_

        # Linear output + MSE
        dz4 = (
            2.0 * (output - X) / X.size
        )

        gW4 = (
            a3.T @ dz4
            + self.weight_decay * p["W4"]
        )
        gb4 = dz4.sum(axis=0, keepdims=True)

        # Third hidden layer: tanh
        dz3 = (
            dz4 @ p["W4"].T
        ) * (1.0 - a3 ** 2)

        gW3 = (
            a2.T @ dz3
            + self.weight_decay * p["W3"]
        )
        gb3 = dz3.sum(axis=0, keepdims=True)

        # Bottleneck layer: tanh
        dz2 = (
            dz3 @ p["W3"].T
        ) * (1.0 - a2 ** 2)

        gW2 = (
            a1.T @ dz2
            + self.weight_decay * p["W2"]
        )
        gb2 = dz2.sum(axis=0, keepdims=True)

        # First hidden layer: tanh
        dz1 = (
            dz2 @ p["W2"].T
        ) * (1.0 - a1 ** 2)

        gW1 = (
            X.T @ dz1
            + self.weight_decay * p["W1"]
        )
        gb1 = dz1.sum(axis=0, keepdims=True)

        return {
            "W1": gW1,
            "b1": gb1,
            "W2": gW2,
            "b2": gb2,
            "W3": gW3,
            "b3": gb3,
            "W4": gW4,
            "b4": gb4,
        }

    def fit(self, X_train_normal, X_cal_normal):
        """Fit on Normal flows only."""

        X = self._check_X(X_train_normal)
        X_cal = self._check_X(X_cal_normal)

        rng = np.random.default_rng(
            self.random_state
        )

        self._initialize(rng)

        # Adam optimizer
        m = {
            k: np.zeros_like(value)
            for k, value in self.params_.items()
        }

        v = {
            k: np.zeros_like(value)
            for k, value in self.params_.items()
        }

        t = 0
        best_loss = np.inf
        stale = 0
        best_params = None

        self.history_ = {
            "train_loss": [],
            "cal_loss": [],
        }

        for epoch in range(1, self.epochs + 1):

            indices = rng.permutation(len(X))

            for start in range(
                0, len(indices), self.batch_size
            ):
                batch_ids = indices[
                    start:start + self.batch_size
                ]

                batch = X[batch_ids]

                gradients = self._backward(
                    self._forward(batch)
                )

                t += 1

                for key, grad in gradients.items():

                    m[key] = (
                        0.9 * m[key] + 0.1 * grad
                    )

                    v[key] = (
                        0.999 * v[key]
                        + 0.001 * grad ** 2
                    )

                    m_hat = m[key] / (
                        1.0 - 0.9 ** t
                    )

                    v_hat = v[key] / (
                        1.0 - 0.999 ** t
                    )

                    self.params_[key] -= (
                        self.learning_rate
                        * m_hat
                        / (np.sqrt(v_hat) + 1e-8)
                    )

            train_loss = self._loss(
                self._forward(X)
            )

            cal_loss = self._loss(
                self._forward(X_cal)
            )

            if not (
                np.isfinite(train_loss)
                and np.isfinite(cal_loss)
            ):
                raise FloatingPointError(
                    "Non-finite autoencoder loss."
                )

            self.history_["train_loss"].append(
                train_loss
            )
            self.history_["cal_loss"].append(
                cal_loss
            )

            if cal_loss < best_loss - 1e-6:
                best_loss = cal_loss
                self.best_epoch_ = epoch

                best_params = {
                    key: value.copy()
                    for key, value
                    in self.params_.items()
                }

                stale = 0

            else:
                stale += 1

                if stale >= self.patience:
                    break

        self.params_ = best_params

        self.epochs_ran_ = len(
            self.history_["train_loss"]
        )

        self.best_cal_loss_ = best_loss

        return self

    def reconstruct(self, X):
        if not hasattr(self, "params_"):
            raise RuntimeError(
                "Autoencoder is not fitted."
            )

        X = self._check_X(X)

        return self._forward(X)[-1]

    def anomaly_score(self, X):
        X = self._check_X(X)

        reconstructed = self.reconstruct(X)

        return np.mean(
            (reconstructed - X) ** 2,
            axis=1,
        )

"""
Mô hình học cách tái tạo bốn đặc trưng của Flow Normal.
    Sai số tái tạo được tính bằng MSE; giá trị càng lớn thì Flow càng khác những mẫu mà mạng có thể tái tạo tốt.

Chúng ta sẽ chọn một ngưỡng bất thường từ tập Normal Calibration riêng biệt,
    rồi đánh giá trên tập Validation chưa dùng để chọn ngưỡng.

"""