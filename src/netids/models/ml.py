"""Reproducible supervised ML pipelines.

Models are returned unfitted.
Fit only on training data.
"""

from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from netids.features.preprocessing import (
    FeatureContractTransformer,
)


def make_ml_pipeline(
    name: str,
    random_state: int = 42,
) -> Pipeline:
    """Build an unfitted ML pipeline."""

    steps = [
        ("contract", FeatureContractTransformer())
    ]

    if name == "logistic_regression":
        steps.extend([
            ("scaler", StandardScaler()),
            ("classifier", LogisticRegression(
                class_weight="balanced",
                max_iter=2000,
                random_state=random_state,
            )),
        ])

    elif name == "random_forest":
        steps.append((
            "classifier",
            RandomForestClassifier(
                n_estimators=200,
                min_samples_leaf=3,
                class_weight="balanced_subsample",
                n_jobs=-1,
                random_state=random_state,
            )
        ))

    else:
        raise ValueError(
            f"Unknown ML pipeline: {name}"
        )

    return Pipeline(steps)
