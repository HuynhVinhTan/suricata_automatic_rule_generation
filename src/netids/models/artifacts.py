"""Save and restore trusted, fitted scikit-learn ML pipelines.

Development artifact for flow_features_v0.1.
SHA-256 checks integrity, not authenticity.
Never load joblib files from untrusted sources.
"""

from __future__ import annotations

import hashlib
import json
import platform
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import sklearn

from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.utils.validation import check_is_fitted

from netids.features.schema import FEATURE_COLUMNS, SCHEMA_VERSION


_MODEL_CLASSES = {
    "random_forest": RandomForestClassifier,
    "logistic_regression": LogisticRegression,
}


def _sha256(path: Path) -> str:
    h = hashlib.sha256()

    with path.open("rb") as file:
        for block in iter(
            lambda: file.read(1024 * 1024),
            b"",
        ):
            h.update(block)

    return h.hexdigest()


def _validate_pipeline(
    pipeline: Pipeline,
    model_name: str,
) -> None:

    if not isinstance(pipeline, Pipeline):
        raise TypeError("Expected a scikit-learn Pipeline.")

    if model_name not in _MODEL_CLASSES:
        raise ValueError(f"Unknown model: {model_name}")

    if not pipeline.steps or pipeline.steps[0][0] != "contract":
        raise ValueError(
            "The pipeline must start with the feature contract."
        )

    classifier = pipeline.named_steps.get("classifier")

    if type(classifier) is not _MODEL_CLASSES[model_name]:
        raise ValueError(
            "Classifier does not match model_name."
        )

    check_is_fitted(classifier)

    if not np.array_equal(
        np.asarray(classifier.classes_),
        np.array([0, 1]),
    ):
        raise ValueError(
            "Expected fitted classifier with classes [0, 1]."
        )


def save_ml_artifact(
    pipeline: Pipeline,
    directory: str | Path,
    *,
    model_name: str,
    y_train: Any,
) -> dict:
    """Save an artifact without overwriting previous versions."""

    _validate_pipeline(pipeline, model_name)

    classes, counts = np.unique(
        np.asarray(y_train),
        return_counts=True,
    )

    if not np.array_equal(classes, [0, 1]):
        raise ValueError(
            "Training labels must contain 0 and 1."
        )

    folder = Path(directory)

    folder.mkdir(
        parents=True,
        exist_ok=False,
    )

    model_path = folder / "pipeline.joblib"

    joblib.dump(
        pipeline,
        model_path,
        compress=3,
    )

    metadata = {
        "artifact_version": 1,
        "status": "development_only",
        "model_name": model_name,
        "schema_version": SCHEMA_VERSION,
        "feature_columns": list(FEATURE_COLUMNS),
        "training_records": int(counts.sum()),
        "train_class_counts": {
            str(int(label)): int(count)
            for label, count in zip(classes, counts)
        },
        "python_version": platform.python_version(),
        "sklearn_version": sklearn.__version__,
        "created_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "decision_threshold": 0.5,
        "threshold_provenance": {
            "decision_threshold": 0.5,
            "status": "development_only",
        },
        "model_sha256": _sha256(model_path),
    }

    metadata_path = folder / "metadata.json"

    metadata_path.write_text(
        json.dumps(
            metadata,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    return metadata


def load_ml_artifact(
    directory: str | Path,
) -> tuple[Pipeline, dict]:
    """Load only locally created, trusted model artifacts."""

    folder = Path(directory)

    metadata_path = folder / "metadata.json"

    metadata = json.loads(
        metadata_path.read_text(encoding="utf-8")
    )

    if metadata.get("artifact_version") != 1:
        raise ValueError("Unsupported artifact version.")

    if metadata.get("status") == "demo_only" or metadata.get("demo_only") is True:
        raise ValueError("Production loader rejects showcase demo_only artifacts.")

    if metadata.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("Schema version mismatch.")

    if metadata.get("feature_columns") != list(FEATURE_COLUMNS):
        raise ValueError("Feature order mismatch.")

    if metadata.get("sklearn_version") != sklearn.__version__:
        raise RuntimeError("scikit-learn version mismatch.")

    model_name = metadata.get("model_name")

    if model_name not in _MODEL_CLASSES:
        raise ValueError("Unknown model name.")

    model_path = folder / "pipeline.joblib"

    if _sha256(model_path) != metadata.get("model_sha256"):
        raise ValueError("Model checksum mismatch.")

    # Warning: joblib deserialization can execute Python code.
    # Only load locally created, trusted model artifacts.
    pipeline = joblib.load(model_path)

    _validate_pipeline(pipeline, model_name)

    return pipeline, metadata
