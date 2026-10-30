"""Synthetic contract tests for UNSW-NB15 adapter."""

import tempfile
import unittest
from pathlib import Path

import numpy as np

from netids.adapters.unsw import (
    FEATURES,
    load_unsw_csv,
)


HEADER = (
    "dur,proto,spkts,dpkts,"
    "sbytes,dbytes,label,attack_cat\n"
)


class TestUNSWAdapter(unittest.TestCase):

    def make_csv(self, rows):
        folder = tempfile.TemporaryDirectory()

        self.addCleanup(folder.cleanup)

        path = Path(folder.name) / "fixture.csv"

        path.write_text(
            HEADER + rows,
            encoding="utf-8",
        )

        return path

    def test_features_and_protocol_coverage(self):
        path = self.make_csv(
            "1,tcp,2,3,100,200,0,Normal\n"
            "2,udp,1,0,50,0,1,Exploits\n"
            "3,icmp,4,0,80,0,1,Generic\n"
        )

        data = load_unsw_csv(path)

        self.assertEqual(
            FEATURES,
            (
                "protocol_tcp",
                "duration_log",
                "packets_log",
                "bytes_log",
            ),
        )

        self.assertEqual(
            (
                data.original_rows,
                data.included_rows,
                data.excluded_protocol_rows,
            ),
            (3, 2, 1),
        )

        self.assertEqual(
            data.X.shape,
            (2, 4),
        )

        self.assertEqual(
            data.y.tolist(),
            [0, 1],
        )

        self.assertEqual(
            data.source_row_indices.tolist(),
            [0, 1],
        )

        np.testing.assert_allclose(
            data.X[0],
            [
                1,
                np.log1p(1),
                np.log1p(5),
                np.log1p(300),
            ],
        )

        self.assertEqual(
            data.attack_categories.tolist(),
            ["Normal", "Exploits"],
        )

    def test_reject_bad_label(self):
        path = self.make_csv(
            "1,tcp,2,3,100,200,2,Normal\n"
        )

        with self.assertRaisesRegex(
            ValueError,
            "binary label",
        ):
            load_unsw_csv(path)

    def test_reject_negative_feature(self):
        path = self.make_csv(
            "-1,tcp,2,3,100,200,0,Normal\n"
        )

        with self.assertRaisesRegex(
            ValueError,
            "negative",
        ):
            load_unsw_csv(path)

    def test_reject_missing_columns(self):
        path = self.make_csv(
            "1,tcp,2,3,100,200,0,Normal\n"
        )

        path.write_text(
            "dur,proto,label\n1,tcp,0\n",
            encoding="utf-8",
        )

        with self.assertRaisesRegex(
            ValueError,
            "Missing UNSW",
        ):
            load_unsw_csv(path)

    def test_reject_unsupported_only(self):
        path = self.make_csv(
            "1,icmp,2,3,100,200,0,Normal\n"
        )

        with self.assertRaisesRegex(
            ValueError,
            "No supported",
        ):
            load_unsw_csv(path)


if __name__ == "__main__":
    unittest.main()