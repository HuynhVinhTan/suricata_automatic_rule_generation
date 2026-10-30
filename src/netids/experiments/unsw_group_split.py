"""Feature-group-disjoint UNSW split, experiment version 02."""

import json
from pathlib import Path

import numpy as np
from sklearn.model_selection import StratifiedGroupKFold

from netids.adapters.unsw import FEATURES, load_unsw_csv
from netids.experiments import unsw_ml_development as ml


SEED = 42
FOLDS = 7
OUTPUT = Path("artifacts/experiments/unsw_group_split_v02")


def make_partitions(X, y):
    X = np.asarray(X, dtype=np.float64)
    y = np.asarray(y)

    if X.ndim != 2 or X.shape[1] != 4:
        raise ValueError("Expected four UNSW features")

    if (
        len(X) != len(y)
        or len(X) == 0
        or not np.isfinite(X).all()
        or set(np.unique(y).tolist()) != {0, 1}
    ):
        raise ValueError("Invalid features or binary labels")

    _, groups = np.unique(
        X, axis=0, return_inverse=True
    )

    splitter = StratifiedGroupKFold(
        n_splits=FOLDS,
        shuffle=True,
        random_state=SEED,
    )

    fold_id = np.full(len(y), -1, dtype=np.int8)

    for fold_number, (_, held_out) in enumerate(
        splitter.split(X, y, groups)
    ):
        if np.any(fold_id[held_out] != -1):
            raise ValueError("Duplicate fold assignment")

        fold_id[held_out] = fold_number

    if np.any(fold_id == -1):
        raise ValueError("Unassigned rows")

    partitions = {
        "development": np.flatnonzero(fold_id >= 2),
        "validation": np.flatnonzero(fold_id == 0),
        "calibration": np.flatnonzero(fold_id == 1),
    }

    combined = np.concatenate(list(partitions.values()))

    if not np.array_equal(
        np.sort(combined), np.arange(len(y))
    ):
        raise ValueError("Overlapping or missing rows")

    for name, indices in partitions.items():
        if not len(indices):
            raise ValueError(f"Empty partition: {name}")

        if set(np.unique(y[indices]).tolist()) != {0, 1}:
            raise ValueError(
                f"Missing class in partition: {name}"
            )

    names = list(partitions)

    for i, name_a in enumerate(names):
        for name_b in names[i + 1:]:
            a = np.unique(groups[partitions[name_a]])
            b = np.unique(groups[partitions[name_b]])

            if np.intersect1d(a, b).size:
                raise ValueError(
                    f"Feature-group overlap: {name_a}/{name_b}"
                )

    return partitions, groups


def describe(y, groups, indices):
    values, counts = np.unique(
        y[indices], return_counts=True
    )

    labels = dict(zip(
        map(int, values),
        map(int, counts),
    ))

    return {
        "rows": int(len(indices)),
        "normal": labels.get(0, 0),
        "attack": labels.get(1, 0),
        "attack_prevalence": float(np.mean(y[indices] == 1)),
        "unique_feature_groups": int(
            len(np.unique(groups[indices]))
        ),
    }


def prepare():
    if OUTPUT.exists():
        raise FileExistsError(
            "v02 split already exists; refusing overwrite"
        )

    source_sha = ml.sha256(ml.TRAIN_FILE)

    if source_sha != ml.EXPECTED_TRAIN_SHA256:
        raise ValueError("UNSW training CSV SHA256 mismatch")

    data = load_unsw_csv(ml.TRAIN_FILE)

    if len(data.y) != 143229:
        raise ValueError("Unexpected UNSW TCP/UDP row count")

    partitions, groups = make_partitions(data.X, data.y)

    info = {
        name: describe(data.y, groups, indices)
        for name, indices in partitions.items()
    }

    manifest = {
        "experiment": "unsw_group_split_v02",
        "status": "SPLIT_PREPARED_NOT_TRAINED",
        "dataset": "UNSW-NB15",
        "train_file": ml.TRAIN_FILE.as_posix(),
        "train_sha256": source_sha,
        "feature_names": list(FEATURES),
        "seed": SEED,
        "method": "StratifiedGroupKFold",
        "n_folds": FOLDS,
        "fold_assignments": {
            "validation": [0],
            "calibration": [1],
            "development": [2, 3, 4, 5, 6],
        },
        "group_definition": (
            "Exact equality of all four transformed "
            "numeric feature values"
        ),
        "unique_feature_groups": int(
            len(np.unique(groups))
        ),
        "partitions": info,
        "exact_feature_group_overlap": 0,
        "official_test_scored": False,
        "limitations": [
            "Feature-disjoint is not host-disjoint.",
            "Feature-disjoint is not time-disjoint.",
            "Stratification may not perfectly balance "
            "classes when groups have different sizes.",
        ],
    }

    OUTPUT.mkdir(parents=True, exist_ok=False)

    np.savez_compressed(
        OUTPUT / "split_indices.npz",
        **partitions,
    )

    manifest["split_sha256"] = ml.sha256(
        OUTPUT / "split_indices.npz"
    )

    with (OUTPUT / "manifest.json").open(
        "x", encoding="utf-8"
    ) as stream:
        json.dump(manifest, stream, indent=2)
        stream.write("\n")

    print("\n=== UNSW GROUP-DISJOINT SPLIT V02 ===")
    print("Input rows:", len(data.y))
    print(
        "Unique four-feature groups:",
        manifest["unique_feature_groups"],
    )

    for name, stats in info.items():
        print(
            f"{name}: "
            f"rows={stats['rows']} "
            f"normal={stats['normal']} "
            f"attack={stats['attack']} "
            f"attack_share={stats['attack_prevalence']:.4f} "
            f"groups={stats['unique_feature_groups']}"
        )

    print("Exact feature-group overlap: 0")
    print("Split SHA256:", manifest["split_sha256"])
    print("Manifest:", OUTPUT / "manifest.json")
    print("PASS: UNSW GROUP SPLIT V02 PREPARED")
    print("NO MODEL TRAINING")
    print("OFFICIAL TEST NOT ACCESSED")
    print("PREVIOUS ARTIFACTS PRESERVED")