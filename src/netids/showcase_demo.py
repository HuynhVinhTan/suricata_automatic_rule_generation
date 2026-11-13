"""Isolated, review-only EVE-native showcase model support."""

from __future__ import annotations

import hashlib
import json
import math
import re
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.pipeline import Pipeline
from sklearn.utils.validation import check_is_fitted

from netids.adapters.suricata import suricata_eve_to_features
from netids.features.schema import FEATURE_COLUMNS, SCHEMA_VERSION, validate_feature_matrix


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_showcase_demo_artifact(directory: str | Path) -> tuple[Pipeline, dict]:
    folder = Path(directory)
    metadata = json.loads((folder / "metadata.json").read_text(encoding="utf-8"))
    if (metadata.get("artifact_version") != 1 or metadata.get("status") != "demo_only" or
            metadata.get("demo_only") is not True or metadata.get("profile") != "showcase_demo"):
        raise ValueError("showcase artifact must be explicitly demo_only")
    if metadata.get("schema_version") != SCHEMA_VERSION or metadata.get("feature_columns") != list(FEATURE_COLUMNS):
        raise ValueError("showcase artifact feature schema mismatch")
    if metadata.get("sklearn_version") not in (None, sklearn.__version__):
        raise RuntimeError("scikit-learn version mismatch")
    model_path = folder / "pipeline.joblib"
    if not re.fullmatch(r"[0-9a-f]{64}", str(metadata.get("model_sha256", ""))) or _sha256(model_path) != metadata["model_sha256"]:
        raise ValueError("showcase model checksum mismatch")
    pipeline = joblib.load(model_path)
    if not isinstance(pipeline, Pipeline) or not pipeline.steps or pipeline.steps[0][0] != "contract":
        raise ValueError("showcase pipeline must start with the feature contract")
    classifier = pipeline.named_steps.get("classifier")
    check_is_fitted(classifier)
    if list(getattr(classifier, "classes_", [])) != [0, 1]:
        raise ValueError("showcase model must expose binary classes [0, 1]")
    threshold = metadata.get("decision_threshold")
    if type(threshold) not in (int, float) or not math.isfinite(float(threshold)) or not 0 <= float(threshold) <= 1:
        raise ValueError("showcase threshold is invalid")
    provenance = metadata.get("threshold_provenance", {})
    if (provenance.get("status") != "demo_only" or provenance.get("decision_threshold") != threshold or
            not isinstance(provenance.get("calibration_method"), str) or
            not isinstance(provenance.get("calibration_version"), str) or
            not re.fullmatch(r"[0-9a-f]{64}", str(provenance.get("calibration_manifest_sha256", "")))):
        raise ValueError("showcase threshold/calibration provenance is incomplete")
    source = metadata.get("source_dataset", {})
    for key in ("development_manifest_sha256", "calibration_manifest_sha256", "holdout_manifest_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", str(source.get(key, ""))):
            raise ValueError("showcase split manifest provenance is incomplete")
    if source.get("split_disjointness") != "verified" or not isinstance(source.get("split_plan"), dict):
        raise ValueError("showcase split disjointness evidence is incomplete")
    return pipeline, metadata


class ShowcaseDemoFlowModelAdapter:
    """Adapter with deliberately non-production output and provenance."""

    def __init__(self, model, metadata: dict):
        if metadata.get("status") != "demo_only" or metadata.get("demo_only") is not True:
            raise ValueError("showcase adapter requires demo_only artifact")
        if metadata.get("schema_version") != SCHEMA_VERSION or metadata.get("feature_columns") != list(FEATURE_COLUMNS):
            raise ValueError("showcase feature order mismatch")
        if not callable(getattr(model, "predict_proba", None)):
            raise ValueError("showcase model must expose callable predict_proba")
        self.model = model
        self.metadata = dict(metadata)
        self.decision_threshold = float(metadata["decision_threshold"])

    def infer(self, event: dict) -> dict:
        features = suricata_eve_to_features(event)
        matrix = validate_feature_matrix(pd.DataFrame([features]))
        scores = self.model.predict_proba(matrix)
        if scores.shape != (1, 2):
            raise ValueError("Model returned an invalid probability matrix")
        score = float(scores[0, 1])
        return {
            "features": features, "score": score, "anomalous": score >= self.decision_threshold,
            "profile": "showcase_demo", "demo_only": True, "approved": False,
            "deployable": False, "deployed": False, "review_state": "REVIEW_ONLY",
            "model_sha256": self.metadata["model_sha256"],
            "data_lineage": self.metadata.get("source_dataset"),
            "calibration_lineage": self.metadata.get("threshold_provenance"),
        }
