"""Safety tests for the canonical experiment CLI."""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from netids.experiments.run import dispatch


class TestExperimentCLI(unittest.TestCase):

    def test_develop_refuses_existing_output(self):
        with tempfile.TemporaryDirectory() as folder:
            training = Mock()

            module = SimpleNamespace(
                OUTPUT_DIR=Path(folder),
                FIGURE_DIR=Path(folder) / "figures",
                main=training,
            )

            with patch(
                "netids.experiments.run.importlib.import_module",
                return_value=module,
            ):
                with self.assertRaises(FileExistsError):
                    dispatch("unsw-nb15", "develop")

            training.assert_not_called()

    def test_unimplemented_stages_do_not_train(self):
        for stage in ("calibrate", "test"):
            with self.subTest(stage=stage):
                with patch(
                    "netids.experiments.run.importlib.import_module"
                ) as imported:
                    with self.assertRaises(
                        NotImplementedError
                    ):
                        dispatch("unsw-nb15", stage)

                    imported.assert_not_called()

    def test_unknown_dataset_rejected(self):
        with self.assertRaises(ValueError):
            dispatch("ctu-13", "report")


if __name__ == "__main__":
    unittest.main()