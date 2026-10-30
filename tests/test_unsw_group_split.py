"""Tests for feature-group-disjoint partitioning."""

import unittest

import numpy as np

from netids.experiments.unsw_group_split import make_partitions


class TestUNSWGroupSplit(unittest.TestCase):

    def make_fixture(self):
        ids = np.arange(70, dtype=np.float64)

        unique_X = np.column_stack((
            ids,
            np.zeros(70),
            np.zeros(70),
            np.zeros(70),
        ))

        X = np.repeat(unique_X, 2, axis=0)

        y = np.repeat(
            np.array([0] * 35 + [1] * 35),
            2,
        )

        return X, y

    def test_group_disjoint_and_complete(self):
        X, y = self.make_fixture()
        parts, groups = make_partitions(X, y)

        combined = np.concatenate(list(parts.values()))

        np.testing.assert_array_equal(
            np.sort(combined), np.arange(len(y))
        )

        for first in parts:
            for second in parts:
                if first == second:
                    continue

                self.assertEqual(
                    np.intersect1d(
                        groups[parts[first]],
                        groups[parts[second]],
                    ).size,
                    0,
                )

    def test_deterministic(self):
        X, y = self.make_fixture()

        a, _ = make_partitions(X, y)
        b, _ = make_partitions(X, y)

        for name in a:
            np.testing.assert_array_equal(
                a[name], b[name]
            )

    def test_reject_invalid_input(self):
        X, y = self.make_fixture()

        with self.assertRaises(ValueError):
            make_partitions(X[:, :2], y)


if __name__ == "__main__":
    unittest.main()