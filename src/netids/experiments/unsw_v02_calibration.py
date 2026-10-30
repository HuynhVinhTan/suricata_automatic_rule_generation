"""UNSW v02 Normal-only threshold calibration.

Only called through the canonical experiments.run CLI.
No training. No official test. No model overwrite.
"""

import hashlib
import json
from pathlib import Path

import joblib
import numpy as np

from netids.adapters.unsw import FEATURES
from netids.experiments import unsw_v02_development as v02
from netids.experiments import unsw_dl_development as dl


CONFIG = Path(
    "configs/experiments/unsw_nb15_v02_calibration.json"
)
OUTPUT = Path(
    "artifacts/experiments/unsw_v02_calibration"
)


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(
            lambda: stream.read(1024 * 1024), b""
        ):
            h.update(block)
    return h.hexdigest()


def threshold_for_budget(scores, budget):
    """Pick a >= threshold with empirical Normal FPR <= budget.

    Uses no Attack calibration labels or scores.
    Handles tied Normal scores conservatively.
    """
    values = np.asarray(scores, dtype=np.float64).reshape(-1)

    if (
        len(values) == 0
        or not np.isfinite(values).all()
        or not (0 <= budget < 1)
    ):
        raise ValueError("Invalid threshold-calibration inputs")

    allowed_fp = int(np.floor(len(values) * budget))
    ordered = np.sort(values)

    # A score strictly higher than this boundary ensures
    # no more than allowed_fp Normal examples are flagged.
    boundary = ordered[len(values) - allowed_fp - 1]
    threshold = float(np.nextafter(boundary, np.inf))

    if not np.isfinite(threshold):
        raise ValueError("No finite threshold can satisfy budget")

    flagged = int(np.count_nonzero(values >= threshold))

    if flagged > allowed_fp:
        raise ValueError("Calibration FPR budget violated")

    return threshold, flagged


def score_model(family, bundle, X):
    if (
        bundle.get("family") != family
        or bundle.get("features") != list(FEATURES)
    ):
        raise ValueError("Frozen model feature contract mismatch")

    model = bundle["model"]
    scaler = bundle["scaler"]

    if family in ("RF", "LogReg"):
        if scaler is not None:
            raise ValueError("Unexpected external ML scaler")

        classes = np.asarray(model.classes_)

        if not np.array_equal(classes, [0, 1]):
            raise ValueError("Unexpected classifier class order")

        values = model.predict_proba(X)[:, 1]

    elif family == "MLP":
        if scaler is None:
            raise ValueError("Missing MLP training scaler")

        values = dl.positive_probability(
            model.predict_proba(scaler.transform(X)),
            len(X),
        )

    elif family == "AE":
        if scaler is None:
            raise ValueError("Missing AE training scaler")

        values = model.anomaly_score(
            scaler.transform(X)
        )

    else:
        raise ValueError("Unsupported model family")

    values = np.asarray(
        values, dtype=np.float64
    ).reshape(-1)

    if values.shape != (len(X),):
        raise ValueError("Incorrect calibration score shape")

    if not np.isfinite(values).all():
        raise ValueError("Non-finite calibration scores")

    if family == "AE":
        if (values < 0).any():
            raise ValueError("Invalid negative anomaly score")
    else:
        if ((values < 0) | (values > 1)).any():
            raise ValueError("Invalid attack probability")

    return values


def run():
    if OUTPUT.exists():
        raise FileExistsError(
            "Calibration already exists; refusing overwrite"
        )

    config = json.loads(
        CONFIG.read_text(encoding="utf-8")
    )

    families = ["LogReg", "RF", "MLP", "AE"]
    budget = config["normal_calibration_fpr_budget"]

    if (
        config.get("experiment") != "unsw_v02_calibration"
        or config.get("model_families") != families
        or config.get("decision_rule") != "score >= threshold"
        or config.get("policy")
        != "normal_calibration_only_no_attack_threshold_tuning"
        or not isinstance(budget, (int, float))
        or not (0 < budget < 1)
    ):
        raise ValueError("Unexpected calibration configuration")

    # Validate frozen development artifacts before loading.
    v02.verify()

    data, dev, val, cal, split_sha = v02.validate_inputs()

    development_summary_path = v02.OUTPUT / "summary.json"
    development_summary = json.loads(
        development_summary_path.read_text(encoding="utf-8")
    )

    if (
        development_summary.get("status") != "DEVELOPMENT_ONLY"
        or development_summary.get("reserved_calibration_used") is not False
        or development_summary.get("official_test_accessed") is not False
    ):
        raise ValueError("Invalid development provenance")

    # Only the Normal part of the reserved Calibration
    # partition is used for threshold estimation.
    normal_cal = cal[data.y[cal] == 0]

    if (
        not len(normal_cal)
        or len(normal_cal) != 7578
        or np.intersect1d(normal_cal, dev).size
        or np.intersect1d(normal_cal, val).size
    ):
        raise ValueError("Unexpected Normal calibration cohort")

    X_normal = data.X[normal_cal]

    records = {}
    all_scores = {}

    print("=== UNSW V02 NORMAL-ONLY CALIBRATION ===")
    print("Normal calibration rows:", len(normal_cal))
    print("FPR budget:", f"{budget:.2%}")
    print("Development models: FROZEN")
    print("Attack calibration labels: NOT USED")
    print("Official test: NOT ACCESSED")

    for family in families:
        selected = development_summary["selected"][family]
        filename = selected["model_file"]

        if Path(filename).name != filename:
            raise ValueError("Unsafe model filename")

        model_path = v02.OUTPUT / filename

        if sha256(model_path) != selected["model_sha256"]:
            raise ValueError("Frozen model hash mismatch")

        # Loads only model artifacts generated locally
        # by this project's previous development run.
        bundle = joblib.load(model_path)

        scores = score_model(family, bundle, X_normal)
        threshold, false_positives = threshold_for_budget(
            scores, budget
        )

        measured_fpr = false_positives / len(normal_cal)

        records[family] = {
            "selected_model": selected["name"],
            "frozen_model_sha256": selected["model_sha256"],
            "validation_ap": selected["validation_ap"],
            "threshold": threshold,
            "score_direction": "higher_means_more_likely_attack",
            "comparison": ">=",
            "normal_calibration_rows": len(normal_cal),
            "allowed_false_positives": int(
                np.floor(len(normal_cal) * budget)
            ),
            "observed_false_positives": false_positives,
            "observed_normal_fpr": measured_fpr,
            "threshold_selected_using_attack_labels": False,
        }

        all_scores[family] = scores

        print(
            f"{family}: {selected['name']} "
            f"threshold={threshold:.12g} "
            f"Normal FP={false_positives}/{len(normal_cal)} "
            f"FPR={measured_fpr:.4%}",
            flush=True,
        )

    # Do not persist anything until every model succeeds.
    OUTPUT.mkdir(parents=True, exist_ok=False)

    score_path = OUTPUT / "normal_calibration_scores.npz"

    np.savez_compressed(
        score_path,
        names=np.asarray(families),
        scores=np.column_stack([
            all_scores[family] for family in families
        ]),
        original_source_rows=(
            data.source_row_indices[normal_cal]
        ),
    )

    manifest = {
        "experiment": "unsw_v02_calibration",
        "status": "FROZEN_THRESHOLD_CANDIDATES",
        "dataset": "UNSW-NB15",
        "config_sha256": sha256(CONFIG),
        "development_summary_sha256": sha256(
            development_summary_path
        ),
        "split_sha256": split_sha,
        "train_sha256": development_summary["train_sha256"],
        "normal_score_file_sha256": sha256(score_path),
        "fpr_budget": budget,
        "normal_calibration_rows": len(normal_cal),
        "official_test_accessed": False,
        "attack_calibration_scores_used": False,
        "model_retrained": False,
        "primary_model_family": "RF",
        "model_selection_basis": (
            "Highest validation AP among the frozen "
            "v02 supervised candidates"
        ),
        "models": records,
        "limitations": [
            "FPR cap applies to Normal calibration rows only.",
            "Does not guarantee test or network operational FPR.",
            "Feature-disjoint is not host/time-disjoint.",
            "Thresholds are post-development calibration outputs.",
        ],
    }

    with (OUTPUT / "manifest.json").open(
        "x", encoding="utf-8"
    ) as stream:
        json.dump(manifest, stream, indent=2)
        stream.write("\n")

    print("\nPASS: UNSW V02 CALIBRATION")
    print("PRIMARY MODEL: RF")
    print("NO MODEL RETRAINING")
    print("NO OFFICIAL TEST SCORING")
    print("MANIFEST:", OUTPUT / "manifest.json")


def verify():
    manifest_path = OUTPUT / "manifest.json"

    manifest = json.loads(
        manifest_path.read_text(encoding="utf-8")
    )

    if (
        manifest.get("experiment") != "unsw_v02_calibration"
        or manifest.get("status")
        != "FROZEN_THRESHOLD_CANDIDATES"
        or manifest.get("official_test_accessed") is not False
        or manifest.get("attack_calibration_scores_used") is not False
        or manifest.get("model_retrained") is not False
        or manifest.get("primary_model_family") != "RF"
    ):
        raise ValueError("Invalid calibration manifest")

    if sha256(CONFIG) != manifest["config_sha256"]:
        raise ValueError("Calibration config hash mismatch")

    if sha256(
        v02.OUTPUT / "summary.json"
    ) != manifest["development_summary_sha256"]:
        raise ValueError("Development summary hash mismatch")

    if sha256(
        v02.grouped.OUTPUT / "split_indices.npz"
    ) != manifest["split_sha256"]:
        raise ValueError("Split hash mismatch")

    score_path = OUTPUT / "normal_calibration_scores.npz"

    if sha256(score_path) != manifest[
        "normal_score_file_sha256"
    ]:
        raise ValueError("Calibration scores hash mismatch")

    with np.load(
        score_path, allow_pickle=False
    ) as saved:
        names = saved["names"].tolist()
        matrix = saved["scores"]
        source_rows = saved["original_source_rows"]

    if (
        names != ["LogReg", "RF", "MLP", "AE"]
        or matrix.shape != (
            manifest["normal_calibration_rows"], 4
        )
        or len(source_rows) != len(matrix)
        or not np.isfinite(matrix).all()
    ):
        raise ValueError("Calibration score contract mismatch")

    development = json.loads(
        (v02.OUTPUT / "summary.json").read_text(
            encoding="utf-8"
        )
    )

    for col, family in enumerate(names):
        record = manifest["models"][family]

        threshold, flagged = threshold_for_budget(
            matrix[:, col], manifest["fpr_budget"]
        )

        if (
            threshold != record["threshold"]
            or flagged != record["observed_false_positives"]
            or not np.isclose(
                flagged / len(matrix),
                record["observed_normal_fpr"],
                rtol=0,
                atol=1e-15,
            )
        ):
            raise ValueError(
                "Calibrated threshold mismatch: " + family
            )

        selected = development["selected"][family]

        if (
            record["selected_model"] != selected["name"]
            or record["frozen_model_sha256"]
            != selected["model_sha256"]
            or sha256(
                v02.OUTPUT / selected["model_file"]
            ) != selected["model_sha256"]
        ):
            raise ValueError(
                "Frozen model mismatch: " + family
            )

    print("=== VERIFIED UNSW V02 CALIBRATION ===")
    print("Primary model: RF")
    print("FPR budget:", f"{manifest['fpr_budget']:.2%}")

    for family in names:
        record = manifest["models"][family]

        print(
            f"{family}: threshold={record['threshold']:.12g} "
            f"Normal FP={record['observed_false_positives']} "
            f"FPR={record['observed_normal_fpr']:.4%}"
        )

    print("PASS: UNSW V02 CALIBRATION VERIFIED")
    print("NO TRAINING PERFORMED")
    print("OFFICIAL TEST NOT ACCESSED")
    print("NO FILES MODIFIED")