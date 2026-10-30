"""Manual MLP for experimental network-flow classification."""

import numpy as np


class NumpyMLP:
    """MLP: input -> 16 ReLU -> 8 ReLU -> sigmoid."""

    def __init__(
        self,
        input_dim=4,
        hidden1=16,
        hidden2=8,
        learning_rate=0.002,
        weight_decay=1e-4,
        epochs=150,
        batch_size=64,
        patience=20,
        random_state=42,
    ):
        self.input_dim = input_dim
        self.hidden1 = hidden1
        self.hidden2 = hidden2
        self.learning_rate = learning_rate
        self.weight_decay = weight_decay
        self.epochs = epochs
        self.batch_size = batch_size
        self.patience = patience
        self.random_state = random_state

    @staticmethod
    def _inputs(X, y=None):
        X = np.asarray(X, dtype=np.float64)

        if X.ndim != 2 or not np.isfinite(X).all():
            raise ValueError("X must be a finite 2-D array.")

        if y is None:
            return X

        y = np.asarray(y, dtype=np.float64).reshape(-1, 1)

        if len(y) != len(X) or not np.isin(y, [0, 1]).all():
            raise ValueError("Invalid binary labels.")

        return X, y

    def _initialize(self, rng):
        dims = (
            self.input_dim,
            self.hidden1,
            self.hidden2,
            1,
        )

        self.params_ = {}

        for i in range(1, 4):
            self.params_[f"W{i}"] = rng.normal(
                0,
                np.sqrt(2.0 / dims[i - 1]),
                size=(dims[i - 1], dims[i]),
            )

            self.params_[f"b{i}"] = np.zeros(
                (1, dims[i])
            )

    def _forward(self, X):
        p = self.params_

        z1 = X @ p["W1"] + p["b1"]
        a1 = np.maximum(z1, 0)

        z2 = a1 @ p["W2"] + p["b2"]
        a2 = np.maximum(z2, 0)

        z3 = a2 @ p["W3"] + p["b3"]

        prob = 1.0 / (
            1.0 + np.exp(-np.clip(z3, -50, 50))
        )

        return {
            "X": X,
            "z1": z1,
            "a1": a1,
            "z2": z2,
            "a2": a2,
            "z3": z3,
            "prob": prob,
        }

    def _loss(self, logits, y, weights):
        # Numerically stable binary cross entropy
        per_row = (
            np.logaddexp(0, logits) - y * logits
        )

        data_loss = (
            np.sum(weights * per_row)
            / np.sum(weights)
        )

        reg = 0.5 * self.weight_decay * sum(
            np.sum(self.params_[f"W{i}"] ** 2)
            for i in range(1, 4)
        )

        return float(data_loss + reg)

    def _backward(self, cache, y, weights):
        p = self.params_

        dz3 = (
            (cache["prob"] - y)
            * (weights / weights.sum())
        )

        gW3 = (
            cache["a2"].T @ dz3
            + self.weight_decay * p["W3"]
        )

        gb3 = dz3.sum(axis=0, keepdims=True)

        dz2 = (
            dz3 @ p["W3"].T
        ) * (cache["z2"] > 0)

        gW2 = (
            cache["a1"].T @ dz2
            + self.weight_decay * p["W2"]
        )

        gb2 = dz2.sum(axis=0, keepdims=True)

        dz1 = (
            dz2 @ p["W2"].T
        ) * (cache["z1"] > 0)

        gW1 = (
            cache["X"].T @ dz1
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
        }

    def fit(self, X, y, X_val, y_val):
        X, y = self._inputs(X, y)
        X_val, y_val = self._inputs(X_val, y_val)

        if (
            X.shape[1] != self.input_dim
            or X_val.shape[1] != self.input_dim
        ):
            raise ValueError("Feature dimension mismatch.")

        counts = np.bincount(
            y.astype(int).ravel(),
            minlength=2,
        )

        if np.any(counts == 0):
            raise ValueError(
                "Training requires both classes."
            )

        # Class weights computed from training only
        class_weights = len(y) / (2 * counts)

        sample_w = class_weights[
            y.astype(int).ravel()
        ].reshape(-1, 1)

        val_w = class_weights[
            y_val.astype(int).ravel()
        ].reshape(-1, 1)

        rng = np.random.default_rng(
            self.random_state
        )

        self._initialize(rng)

        # Adam optimizer state
        m = {
            k: np.zeros_like(v)
            for k, v in self.params_.items()
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
            "val_loss": [],
        }

        for epoch in range(1, self.epochs + 1):
            batches = np.array_split(
                rng.permutation(len(X)),
                max(
                    1,
                    int(np.ceil(
                        len(X) / self.batch_size
                    )),
                ),
            )

            for ids in batches:
                cache = self._forward(X[ids])

                grads = self._backward(
                    cache,
                    y[ids],
                    sample_w[ids],
                )

                t += 1

                for key, grad in grads.items():
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
                        self.learning_rate * m_hat
                        / (np.sqrt(v_hat) + 1e-8)
                    )

            train_cache = self._forward(X)
            val_cache = self._forward(X_val)

            train_loss = self._loss(
                train_cache["z3"], y, sample_w
            )

            val_loss = self._loss(
                val_cache["z3"], y_val, val_w
            )

            self.history_["train_loss"].append(
                train_loss
            )

            self.history_["val_loss"].append(
                val_loss
            )

            if not np.isfinite(val_loss):
                raise FloatingPointError(
                    "Non-finite validation loss."
                )

            # Early stopping
            if val_loss < best_loss - 1e-6:
                best_loss = val_loss

                best_params = {
                    k: value.copy()
                    for k, value in self.params_.items()
                }

                self.best_epoch_ = epoch
                stale = 0
            else:
                stale += 1

                if stale >= self.patience:
                    break

        self.params_ = best_params
        self.epochs_ran_ = len(
            self.history_["train_loss"]
        )
        self.best_val_loss_ = best_loss

        return self

    def predict_proba(self, X):
        if not hasattr(self, "params_"):
            raise RuntimeError("Model is not fitted.")

        X = self._inputs(X)

        if X.shape[1] != self.input_dim:
            raise ValueError("Feature dimension mismatch.")

        prob = self._forward(X)["prob"].ravel()

        return np.column_stack([
            1.0 - prob,
            prob,
        ])

    def predict(self, X):
        return (
            self.predict_proba(X)[:, 1] >= 0.5
        ).astype(int)