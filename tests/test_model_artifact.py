"""Tests for experimental model artifact persistence."""

import json
import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

from netids.models.artifacts import (
    save_ml_artifact,
    load_ml_artifact,
)
from netids.models.ml import make_ml_pipeline


class TestModelArtifact(unittest.TestCase):

    def setUp(self):
        self.X = pd.DataFrame({
            "protocol_tcp": [0, 1, 0, 1, 0, 1],
            "duration_log": [0.1, 2.1, 0.2, 2.4, 0.3, 2.8],
            "packets_log": [1.0, 3.0, 1.0, 4.0, 2.0, 5.0],
            "bytes_log": [2.0, 6.0, 3.0, 7.0, 2.0, 8.0],
        })

        self.y = np.array([0, 1, 0, 1, 0, 1])

        self.model = make_ml_pipeline(
            "random_forest",
            random_state=42,
        )

        self.model.fit(self.X, self.y)

    def _save(self, path):
        return save_ml_artifact(
            self.model,
            path,
            model_name="random_forest",
            y_train=self.y,
        )

    def test_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rf_v0_1"

            metadata = self._save(path)
            restored, readback = load_ml_artifact(path)

            np.testing.assert_allclose(
                self.model.predict_proba(self.X),
                restored.predict_proba(self.X),
                rtol=0,
                atol=0,
            )

            self.assertEqual(
                readback["model_sha256"],
                metadata["model_sha256"],
            )

            self.assertEqual(
                readback["training_records"],
                6,
            )

    def test_refuse_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rf_v0_1"

            self._save(path)

            with self.assertRaises(FileExistsError):
                self._save(path)

    def test_reject_schema_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rf_v0_1"

            self._save(path)

            meta_path = path / "metadata.json"

            metadata = json.loads(
                meta_path.read_text(encoding="utf-8")
            )

            metadata["schema_version"] = "wrong_schema"

            meta_path.write_text(
                json.dumps(metadata),
                encoding="utf-8",
            )

            with self.assertRaises(ValueError):
                load_ml_artifact(path)

    def test_reject_corruption(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rf_v0_1"

            self._save(path)

            with (path / "pipeline.joblib").open("ab") as file:
                file.write(b"CORRUPTED")

            with self.assertRaises(ValueError):
                load_ml_artifact(path)

    def test_production_loader_rejects_showcase_demo(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rf_v0_1"
            self._save(path)
            metadata_path = path / "metadata.json"
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            metadata["status"] = "demo_only"
            metadata["demo_only"] = True
            metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_ml_artifact(path)


if __name__ == "__main__":
    unittest.main()
