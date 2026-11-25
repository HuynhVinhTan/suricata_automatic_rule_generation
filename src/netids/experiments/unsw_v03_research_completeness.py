"""UNSW-NB15 v03 research-completeness experiment.

This module is research-only. It reads the official training CSV only, keeps
raw input untouched, fits learned preprocessing inside each CV fold, and
refuses to invent output when the authorized dataset is unavailable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedGroupKFold, train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from netids.adapters.unsw import FEATURES
from netids.experiments.unsw_v02_calibration import threshold_for_budget
from netids.models.autoencoder import NumpyAutoencoder
from netids.models.dl import NumpyMLP


SEED = 42
FOLDS = 5
NORMAL_FPR_BUDGET = 0.01
TRAIN_FILE = Path("data/raw/unsw-nb15/UNSW_NB15_training-set.csv")
OFFICIAL_TEST_FILE = Path("data/raw/unsw-nb15/UNSW_NB15_testing-set.csv")
OUTPUT = Path("artifacts/experiments/unsw_v03_research_completeness")
V02_DIR = Path("artifacts/experiments/unsw_v02_development")
V02_SPLIT_DIR = Path("artifacts/experiments/unsw_group_split_v02")
REQUIRED_COLUMNS = {"dur", "proto", "spkts", "dpkts", "sbytes", "dbytes", "label"}
PHYSICAL_COLUMNS = ("dur", "spkts", "dpkts", "sbytes", "dbytes")
RAW_METRICS = ("duration_s", "packets", "bytes")
METRIC_NAMES = ("accuracy", "precision", "recall", "f1", "ap", "fpr")


class DatasetUnavailable(FileNotFoundError):
    """The authorized raw dataset is not available."""


@dataclass(frozen=True)
class PreprocessingResult:
    raw: pd.DataFrame
    processed: pd.DataFrame
    original_rows: int
    processed_rows: int
    removed_rows: int
    removal_reasons: dict[str, int]
    raw_duplicate_rows: int
    processed_duplicate_feature_rows: int


def sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_raw(path: str | Path) -> pd.DataFrame:
    path = Path(path)
    if not path.is_file():
        raise DatasetUnavailable(f"Authorized raw dataset is missing: {path}")
    raw = pd.read_csv(path, low_memory=False)
    missing = REQUIRED_COLUMNS - set(raw.columns)
    if missing:
        raise ValueError(f"UNSW raw dataset is missing columns: {sorted(missing)}")
    if raw.empty:
        raise ValueError("UNSW raw dataset is empty")
    return raw


def _feature_matrix(processed: pd.DataFrame) -> np.ndarray:
    values = processed.loc[:, list(FEATURES)].to_numpy(dtype=np.float64)
    if values.ndim != 2 or values.shape[1] != len(FEATURES) or not np.isfinite(values).all():
        raise ValueError("Processed UNSW feature matrix is not finite and 4-dimensional")
    return values


def preprocess_raw(raw_or_path: pd.DataFrame | str | Path) -> PreprocessingResult:
    """Audit and derive features without imputing, clipping or deleting duplicates."""
    raw = _read_raw(raw_or_path) if not isinstance(raw_or_path, pd.DataFrame) else raw_or_path.copy(deep=True)
    missing = REQUIRED_COLUMNS - set(raw.columns)
    if missing:
        raise ValueError(f"UNSW raw dataset is missing columns: {sorted(missing)}")
    numeric = raw.loc[:, PHYSICAL_COLUMNS].apply(pd.to_numeric, errors="coerce")
    protocols = raw["proto"].astype("string").str.strip().str.lower()
    labels = pd.to_numeric(raw["label"], errors="coerce")
    unsupported = ~protocols.isin(["tcp", "udp"])
    bad_numeric = (~np.isfinite(numeric.to_numpy(dtype=np.float64))).any(axis=1) | (numeric < 0).any(axis=1).to_numpy()
    invalid_label = labels.isna().to_numpy() | ~labels.isin([0, 1]).to_numpy()
    valid = ~(unsupported.to_numpy() | bad_numeric | invalid_label)
    reasons = {
        "unsupported_protocol": int(unsupported.to_numpy().sum()),
        "negative_or_nonfinite_numeric": int(bad_numeric.sum()),
        "invalid_binary_label": int(invalid_label.sum()),
    }
    processed = raw.loc[valid].copy()
    processed.loc[:, list(PHYSICAL_COLUMNS)] = numeric.loc[valid, list(PHYSICAL_COLUMNS)].to_numpy()
    processed.loc[:, "proto"] = protocols.loc[valid].to_numpy()
    processed.loc[:, "label"] = labels.loc[valid].astype(np.int8).to_numpy()
    processed.loc[:, "duration_s"] = processed["dur"].astype(float)
    processed.loc[:, "packets"] = processed["spkts"].astype(float) + processed["dpkts"].astype(float)
    processed.loc[:, "bytes"] = processed["sbytes"].astype(float) + processed["dbytes"].astype(float)
    processed.loc[:, "protocol_tcp"] = (processed["proto"] == "tcp").astype(float)
    processed.loc[:, "duration_log"] = np.log1p(processed["duration_s"])
    processed.loc[:, "packets_log"] = np.log1p(processed["packets"])
    processed.loc[:, "bytes_log"] = np.log1p(processed["bytes"])
    processed = processed.reset_index(names="source_raw_row")
    feature_dupes = processed.duplicated(subset=list(FEATURES), keep=False)
    return PreprocessingResult(
        raw=raw,
        processed=processed,
        original_rows=int(len(raw)),
        processed_rows=int(len(processed)),
        removed_rows=int((~valid).sum()),
        removal_reasons=reasons,
        raw_duplicate_rows=int(raw.duplicated(keep=False).sum()),
        processed_duplicate_feature_rows=int(feature_dupes.sum()),
    )


def summarize_metrics(y_true: np.ndarray, scores: np.ndarray, threshold: float) -> dict[str, float]:
    y_true = np.asarray(y_true, dtype=np.int8).reshape(-1)
    scores = np.asarray(scores, dtype=np.float64).reshape(-1)
    if len(y_true) == 0 or len(y_true) != len(scores) or not np.isfinite(scores).all():
        raise ValueError("Metric inputs must be non-empty and finite")
    predictions = (scores >= threshold).astype(np.int8)
    tn, fp, _, _ = confusion_matrix(y_true, predictions, labels=[0, 1]).ravel()
    return {
        "accuracy": float(accuracy_score(y_true, predictions)),
        "precision": float(precision_score(y_true, predictions, zero_division=0)),
        "recall": float(recall_score(y_true, predictions, zero_division=0)),
        "f1": float(f1_score(y_true, predictions, zero_division=0)),
        "ap": float(average_precision_score(y_true, scores)),
        "fpr": float(fp / (tn + fp)) if (tn + fp) else 0.0,
    }


def _confusion(y_true: np.ndarray, scores: np.ndarray, threshold: float) -> dict[str, int]:
    tn, fp, fn, tp = map(int, confusion_matrix(y_true, scores >= threshold, labels=[0, 1]).ravel())
    return {"tn": tn, "fp": fp, "fn": fn, "tp": tp}


def _group_ids(X: np.ndarray) -> np.ndarray:
    _, groups = np.unique(X, axis=0, return_inverse=True)
    return groups.astype(np.int64)


def _model_factories() -> dict[str, Any]:
    """Selected v02 family configurations; no v02 model is loaded or overwritten."""
    return {
        "LogReg": lambda: make_pipeline(StandardScaler(), LogisticRegression(C=1.0, class_weight="balanced", max_iter=1000, random_state=SEED)),
        "RF": lambda: RandomForestClassifier(n_estimators=120, max_depth=16, min_samples_leaf=5, class_weight="balanced_subsample", random_state=SEED, n_jobs=-1),
        "MLP": lambda: NumpyMLP(input_dim=4, hidden1=24, hidden2=12, epochs=50, batch_size=256, patience=8, random_state=SEED),
        "AE": lambda: NumpyAutoencoder(input_dim=4, hidden_dim=12, bottleneck_dim=3, epochs=60, batch_size=256, patience=8, random_state=SEED),
    }


def _load_v02_partition(data: PreprocessingResult) -> tuple[np.ndarray, dict[str, Any]]:
    split_path = V02_SPLIT_DIR / "split_indices.npz"
    manifest_path = V02_SPLIT_DIR / "manifest.json"
    if not split_path.is_file() or not manifest_path.is_file():
        raise FileNotFoundError("Frozen v02 split manifest is missing")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    with np.load(split_path, allow_pickle=False) as split:
        dev = split["development"].astype(np.int64)
        val = split["validation"].astype(np.int64)
        cal = split["calibration"].astype(np.int64)
    all_indices = np.concatenate((dev, val, cal))
    if len(data.processed) != len(all_indices) or not np.array_equal(np.sort(all_indices), np.arange(len(data.processed))):
        raise ValueError("Processed rows do not match frozen v02 partition contract")
    return _feature_matrix(data.processed), {"development": dev, "validation": val, "calibration": cal, "manifest": manifest, "split_sha256": sha256(split_path)}


def leakage_audit(data: PreprocessingResult, partition: dict[str, Any]) -> dict[str, Any]:
    X = _feature_matrix(data.processed)
    y = data.processed["label"].to_numpy(dtype=np.int8)
    groups = _group_ids(X)
    conflicts = sum(np.unique(y[groups == group]).size > 1 for group in np.unique(groups))
    partitions = {name: partition[name] for name in ("development", "validation", "calibration")}
    overlap = {}
    for left_name, left in partitions.items():
        for right_name, right in partitions.items():
            if left_name < right_name:
                overlap[f"{left_name}_vs_{right_name}"] = int(np.intersect1d(groups[left], groups[right]).size)
    host_time = [name for name in data.processed.columns if any(token in name.lower() for token in ("host", "srcip", "dstip", "timestamp", "time", "addr"))]
    return {
        "status": "COMPLETED",
        "official_test_accessed": False,
        "official_test_path": str(OFFICIAL_TEST_FILE),
        "label_columns_excluded_from_model": ["label", "attack_cat"],
        "model_features": list(FEATURES),
        "direct_label_feature_overlap": sorted(set(FEATURES) & {"label", "attack_cat"}),
        "exact_duplicate_raw_rows": data.raw_duplicate_rows,
        "exact_duplicate_feature_rows": data.processed_duplicate_feature_rows,
        "feature_groups_with_conflicting_binary_labels": int(conflicts),
        "partition_feature_group_overlap": overlap,
        "cv_group_definition": "Exact equality of all four transformed v02 feature values",
        "host_time_leakage": {
            "available_columns": host_time,
            "status": "LIMITED_NOT_AVAILABLE" if not host_time else "AUDIT_FIELDS_PRESENT",
            "limitation": "UNSW-NB15 training contract does not expose a verified host/session/time identity; feature-disjoint is not host/time-disjoint.",
        },
        "official_test_policy": "Frozen official test is not opened, fitted, tuned or scored by v03.",
    }


def _save_eda_figures(processed: pd.DataFrame, directory: Path) -> list[str]:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    directory.mkdir(parents=True, exist_ok=False)
    names = []
    fig, axes = plt.subplots(2, 2, figsize=(14, 9))
    for ax, column, title, unit in zip(axes.ravel(), ("proto", "duration_s", "packets", "bytes"), ("Protocol distribution", "Flow duration", "Packet count", "Byte count"), ("count", "seconds; log x-axis", "packets; log x-axis", "bytes; log x-axis")):
        if column == "proto":
            counts = processed[column].value_counts().sort_index()
            ax.bar(counts.index.astype(str), counts.values, color="#4472C4")
            ax.set_ylabel("Flows")
        else:
            ax.hist(processed[column].to_numpy(dtype=float), bins=50, color="#4472C4", alpha=0.85)
            ax.set_xscale("symlog", linthresh=1e-6)
            ax.set_ylabel("Flows")
        ax.set_title(title); ax.set_xlabel(unit); ax.grid(alpha=0.2)
    fig.suptitle("UNSW-NB15 EDA: protocol, duration, packets and bytes", fontsize=15); fig.tight_layout()
    name = "01_feature_histograms.png"; fig.savefig(directory / name, dpi=300, bbox_inches="tight"); plt.close(fig); names.append(name)
    fig, axes = plt.subplots(2, 2, figsize=(14, 9))
    for ax, column, title, unit in zip(axes.ravel(), RAW_METRICS, ("Duration by class", "Packets by class", "Bytes by class"), ("seconds; log y-axis", "packets; log y-axis", "bytes; log y-axis")):
        normal = processed.loc[processed["label"] == 0, column].to_numpy(dtype=float)
        attack = processed.loc[processed["label"] == 1, column].to_numpy(dtype=float)
        ax.boxplot([normal, attack], labels=["Normal", "Attack"], showfliers=False); ax.set_yscale("symlog", linthresh=1e-6); ax.set_title(title); ax.set_ylabel(unit); ax.grid(alpha=0.2)
    axes[1, 1].axis("off"); fig.suptitle("UNSW-NB15 EDA: Normal vs Attack distributions", fontsize=15); fig.tight_layout()
    name = "02_normal_attack_boxplots.png"; fig.savefig(directory / name, dpi=300, bbox_inches="tight"); plt.close(fig); names.append(name)
    fig, axes = plt.subplots(1, 3, figsize=(18, 5))
    class_counts = processed["label"].map({0: "Normal", 1: "Attack"}).value_counts().reindex(["Normal", "Attack"])
    axes[0].bar(class_counts.index, class_counts.values, color=["#70AD47", "#C00000"]); axes[0].set_title("Class distribution"); axes[0].set_ylabel("Flows")
    protocol_counts = processed["proto"].value_counts().sort_index(); axes[1].bar(protocol_counts.index.astype(str), protocol_counts.values, color="#5B9BD5"); axes[1].set_title("Protocol distribution"); axes[1].set_ylabel("Flows")
    categories = processed["attack_cat"].fillna("UNKNOWN").astype(str).value_counts().sort_values(); axes[2].barh(categories.index, categories.values, color="#ED7D31"); axes[2].set_title("Attack category distribution"); axes[2].set_xlabel("Flows")
    fig.suptitle("UNSW-NB15 label and category distributions", fontsize=15); fig.tight_layout()
    name = "03_class_protocol_attack_category.png"; fig.savefig(directory / name, dpi=300, bbox_inches="tight"); plt.close(fig); names.append(name)
    columns = ["duration_s", "packets", "bytes", "label"]; corr = processed.loc[:, columns].corr(numeric_only=True).to_numpy(dtype=float)
    fig, ax = plt.subplots(figsize=(8, 7)); image = ax.imshow(corr, vmin=-1, vmax=1, cmap="coolwarm"); ax.set_xticks(range(len(columns)), columns); ax.set_yticks(range(len(columns)), columns)
    for row in range(len(columns)):
        for col in range(len(columns)): ax.text(col, row, f"{corr[row, col]:.2f}", ha="center", va="center")
    fig.colorbar(image, ax=ax, label="Pearson correlation"); ax.set_title("UNSW-NB15 numeric feature correlation heatmap"); fig.tight_layout()
    name = "04_correlation_heatmap.png"; fig.savefig(directory / name, dpi=300, bbox_inches="tight"); plt.close(fig); names.append(name)
    return names


def _write_reports(data: PreprocessingResult, partition: dict[str, Any], output: Path) -> None:
    output.joinpath("preprocessing_report.json").write_text(json.dumps({
        "status": "COMPLETED", "raw_rows": data.original_rows, "processed_rows": data.processed_rows, "removed_rows": data.removed_rows,
        "retention_rate": data.processed_rows / data.original_rows, "removal_reasons": data.removal_reasons,
        "raw_duplicate_rows_reported_not_removed": data.raw_duplicate_rows, "processed_duplicate_feature_rows_reported_not_removed": data.processed_duplicate_feature_rows,
        "policy": {"raw_preserved": True, "imputation": "none", "clipping": "none", "duplicate_deletion": "none", "invalid_rows": "excluded only when the existing UNSW flow contract failed"},
    }, indent=2), encoding="utf-8")
    before = data.raw.head(10).copy(); before.insert(0, "stage", "RAW_BEFORE")
    after = data.processed.head(10).copy(); after.insert(0, "stage", "PROCESSED_AFTER")
    pd.concat([before, after], ignore_index=True, sort=False).to_csv(output / "before_after_samples.csv", index=False)
    rows = []
    for stage, table in (("RAW_BEFORE", data.raw), ("PROCESSED_AFTER", data.processed)):
        rows.extend({"stage": stage, "label": str(label), "rows": int(count)} for label, count in table["label"].value_counts(dropna=False).items())
    pd.DataFrame(rows).to_csv(output / "class_distribution_before_after.csv", index=False)
    quantiles = []
    for column in RAW_METRICS:
        values = data.processed[column].to_numpy(dtype=float); q = np.quantile(values, [0.01, .05, .25, .5, .75, .95, .99]); iqr = q[4] - q[2]; lower, upper = q[2] - 1.5 * iqr, q[4] + 1.5 * iqr
        quantiles.append({"feature": column, "q01": q[0], "q05": q[1], "q25": q[2], "q50": q[3], "q75": q[4], "q95": q[5], "q99": q[6], "iqr_lower_fence": lower, "iqr_upper_fence": upper, "iqr_outlier_rows": int(((values < lower) | (values > upper)).sum())})
    pd.DataFrame(quantiles).to_csv(output / "quantiles_and_outliers.csv", index=False)
    (output / "leakage_audit.json").write_text(json.dumps(leakage_audit(data, partition), indent=2), encoding="utf-8")


def _fit_and_score_cv(X: np.ndarray, y: np.ndarray, partition: dict[str, Any], output: Path) -> tuple[dict[str, np.ndarray], dict[str, np.ndarray], list[dict[str, Any]], dict[str, list[dict[str, Any]]], list[str]]:
    dev = partition["development"]; X_dev, y_dev = X[dev], y[dev]; groups = _group_ids(X_dev)
    splitter = StratifiedGroupKFold(n_splits=FOLDS, shuffle=True, random_state=SEED)
    factories = _model_factories(); oof = {family: np.full(len(dev), np.nan) for family in factories}; thresholds = {family: np.full(len(dev), np.nan) for family in factories}
    fold_metrics = []; histories = {family: [] for family in factories}; checkpoint_dir = output / "checkpoints"; checkpoint_dir.mkdir(parents=True, exist_ok=False); checkpoint_names = []
    for fold, (train_rel, test_rel) in enumerate(splitter.split(X_dev, y_dev, groups), start=1):
        X_train, X_test, y_train, y_test = X_dev[train_rel], X_dev[test_rel], y_dev[train_rel], y_dev[test_rel]
        if np.intersect1d(groups[train_rel], groups[test_rel]).size: raise ValueError(f"Fold {fold} has feature-group overlap")
        for family in ("LogReg", "RF"):
            model = factories[family](); model.fit(X_train, y_train); scores = model.predict_proba(X_test)[:, 1]; threshold = .5; oof[family][test_rel] = scores; thresholds[family][test_rel] = threshold
            fold_metrics.append({"fold": fold, "family": family, "train_rows": len(train_rel), "test_rows": len(test_rel), "threshold": threshold, **summarize_metrics(y_test, scores, threshold), **_confusion(y_test, scores, threshold)})
            checkpoint = checkpoint_dir / f"fold_{fold:02d}_{family.lower()}.joblib"; joblib.dump({"family": family, "model": model, "scaler": None, "threshold": threshold, "best_weight_restored": True}, checkpoint, compress=3); checkpoint_names.append(str(checkpoint.relative_to(output)))
        inner_train, inner_stop = train_test_split(np.arange(len(train_rel)), test_size=.20, stratify=y_train, random_state=SEED); scaler = StandardScaler().fit(X_train[inner_train]); model = factories["MLP"](); model.fit(scaler.transform(X_train[inner_train]), y_train[inner_train], scaler.transform(X_train[inner_stop]), y_train[inner_stop]); scores = model.predict_proba(scaler.transform(X_test))[:, 1]; oof["MLP"][test_rel] = scores; thresholds["MLP"][test_rel] = .5
        histories["MLP"].append({"fold": fold, "best_epoch": int(model.best_epoch_), "epochs_ran": int(model.epochs_ran_), "best_validation_loss": float(model.best_val_loss_), "train_loss": [float(v) for v in model.history_["train_loss"]], "validation_loss": [float(v) for v in model.history_["val_loss"]]}); fold_metrics.append({"fold": fold, "family": "MLP", "train_rows": len(train_rel), "test_rows": len(test_rel), "threshold": .5, **summarize_metrics(y_test, scores, .5), **_confusion(y_test, scores, .5)})
        checkpoint = checkpoint_dir / f"fold_{fold:02d}_mlp.joblib"; joblib.dump({"family": "MLP", "model": model, "scaler": scaler, "threshold": .5, "best_epoch": int(model.best_epoch_), "best_weight_restored": True}, checkpoint, compress=3); checkpoint_names.append(str(checkpoint.relative_to(output)))
        normal_positions = np.flatnonzero(y_train == 0)
        ae_train_rel, ae_stop_rel, threshold_rel = np.array_split(normal_positions, 3); ae_scaler = StandardScaler().fit(X_train[ae_train_rel]); ae_model = factories["AE"](); ae_model.fit(ae_scaler.transform(X_train[ae_train_rel]), ae_scaler.transform(X_train[ae_stop_rel])); normal_scores = ae_model.anomaly_score(ae_scaler.transform(X_train[threshold_rel])); threshold, _ = threshold_for_budget(normal_scores, NORMAL_FPR_BUDGET); scores = ae_model.anomaly_score(ae_scaler.transform(X_test)); oof["AE"][test_rel] = scores; thresholds["AE"][test_rel] = threshold
        histories["AE"].append({"fold": fold, "best_epoch": int(ae_model.best_epoch_), "epochs_ran": int(ae_model.epochs_ran_), "best_calibration_loss": float(ae_model.best_cal_loss_), "train_loss": [float(v) for v in ae_model.history_["train_loss"]], "validation_loss": [float(v) for v in ae_model.history_["cal_loss"]], "normal_threshold_rows": len(threshold_rel), "normal_fpr_budget": NORMAL_FPR_BUDGET}); fold_metrics.append({"fold": fold, "family": "AE", "train_rows": len(train_rel), "test_rows": len(test_rel), "threshold": float(threshold), "normal_fpr_budget": NORMAL_FPR_BUDGET, **summarize_metrics(y_test, scores, threshold), **_confusion(y_test, scores, threshold)})
        checkpoint = checkpoint_dir / f"fold_{fold:02d}_ae.joblib"; joblib.dump({"family": "AE", "model": ae_model, "scaler": ae_scaler, "threshold": float(threshold), "best_epoch": int(ae_model.best_epoch_), "best_weight_restored": True, "normal_only_threshold_calibration": True}, checkpoint, compress=3); checkpoint_names.append(str(checkpoint.relative_to(output)))
    if any(not np.isfinite(values).all() for values in list(oof.values()) + list(thresholds.values())): raise ValueError("OOF CV predictions are incomplete")
    return oof, thresholds, fold_metrics, histories, checkpoint_names


def _save_evaluation_figures(y: np.ndarray, oof: dict[str, np.ndarray], thresholds: dict[str, np.ndarray], fold_metrics: list[dict[str, Any]], histories: dict[str, list[dict[str, Any]]], directory: Path) -> list[str]:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from sklearn.metrics import ConfusionMatrixDisplay, precision_recall_curve, roc_curve
    directory.mkdir(parents=True, exist_ok=False); names = []
    for family, scores in oof.items():
        fig, ax = plt.subplots(figsize=(6, 5)); ConfusionMatrixDisplay.from_predictions(y, scores >= thresholds[family], labels=[0, 1], display_labels=["Normal", "Attack"], cmap="Blues", values_format="d", ax=ax); ax.set_title(f"{family} - 5-fold OOF confusion matrix"); fig.tight_layout(); name = f"confusion_matrix_{family.lower()}.png"; fig.savefig(directory / name, dpi=300, bbox_inches="tight"); plt.close(fig); names.append(name)
    fig, ax = plt.subplots(figsize=(8, 6))
    for family, scores in oof.items():
        precision, recall, _ = precision_recall_curve(y, scores); ax.plot(recall, precision, label=f"{family} AP={average_precision_score(y, scores):.4f}")
    ax.set(xlabel="Recall", ylabel="Precision", title="UNSW-NB15 5-fold OOF precision-recall curves", xlim=(0, 1), ylim=(0, 1.02)); ax.legend(); ax.grid(alpha=.2); fig.tight_layout(); name = "pr_curves_oof.png"; fig.savefig(directory / name, dpi=300, bbox_inches="tight"); plt.close(fig); names.append(name)
    fig, ax = plt.subplots(figsize=(8, 6))
    for family, scores in oof.items():
        fpr, tpr, _ = roc_curve(y, scores); ax.plot(fpr, tpr, label=f"{family} ROC-AUC={roc_auc_score(y, scores):.4f}")
    ax.plot([0, 1], [0, 1], "--", color="gray", label="Chance"); ax.set(xlabel="False positive rate", ylabel="True positive rate", title="UNSW-NB15 5-fold OOF ROC curves", xlim=(0, 1), ylim=(0, 1.02)); ax.legend(); ax.grid(alpha=.2); fig.tight_layout(); name = "roc_curves_oof.png"; fig.savefig(directory / name, dpi=300, bbox_inches="tight"); plt.close(fig); names.append(name)
    summary = {family: {metric: [row[metric] for row in fold_metrics if row["family"] == family] for metric in METRIC_NAMES} for family in oof}; fig, axes = plt.subplots(2, 2, figsize=(14, 9))
    for ax, metric in zip(axes.ravel(), METRIC_NAMES[:4]):
        families = list(oof); means = [np.mean(summary[family][metric]) for family in families]; stds = [np.std(summary[family][metric], ddof=1) for family in families]; ax.bar(families, means, yerr=stds, capsize=4, color="#4472C4"); ax.set_title(metric.upper()); ax.set_ylim(0, 1.05); ax.set_ylabel("mean ± std"); ax.grid(axis="y", alpha=.2)
    fig.suptitle("UNSW-NB15 5-fold cross-validation comparison", fontsize=15); fig.tight_layout(); name = "model_comparison_accuracy_precision_recall_f1.png"; fig.savefig(directory / name, dpi=300, bbox_inches="tight"); plt.close(fig); names.append(name)
    for family in ("MLP", "AE"):
        fig, ax = plt.subplots(figsize=(8, 5))
        for history in histories[family]: ax.plot(history["train_loss"], alpha=.45, color="#4472C4"); ax.plot(history["validation_loss"], alpha=.45, color="#C00000")
        ax.set(xlabel="Epoch", ylabel="Loss", title=f"{family} 5-fold training/validation loss"); ax.plot([], [], color="#4472C4", label="Training"); ax.plot([], [], color="#C00000", label="Inner validation"); ax.legend(); ax.grid(alpha=.2); fig.tight_layout(); name = f"training_history_{family.lower()}.png"; fig.savefig(directory / name, dpi=300, bbox_inches="tight"); plt.close(fig); names.append(name)
    return names


def _write_hash_manifest(output: Path, data: PreprocessingResult, partition: dict[str, Any], figures: list[str], checkpoints: list[str]) -> None:
    files = {str(path.relative_to(output)).replace("\\", "/"): sha256(path) for path in output.rglob("*") if path.is_file() and path.name != "manifest.json"}
    v02_summary = json.loads((V02_DIR / "summary.json").read_text(encoding="utf-8"))
    v02_model_hashes = {family: item["model_sha256"] for family, item in v02_summary["selected"].items()}
    manifest = {"experiment": "unsw_v03_research_completeness", "status": "COMPLETED", "dataset": "UNSW-NB15", "seed": SEED, "folds": FOLDS, "feature_names": list(FEATURES), "official_test_accessed": False, "official_test_policy": "never opened by v03", "raw_training_file": str(TRAIN_FILE), "raw_training_sha256": sha256(TRAIN_FILE), "raw_rows": data.original_rows, "processed_rows": data.processed_rows, "removed_rows": data.removed_rows, "v02_split_sha256": partition["split_sha256"], "v02_development_artifact_sha256": sha256(V02_DIR / "summary.json"), "v02_frozen_model_hashes": v02_model_hashes, "figures": figures, "checkpoints": checkpoints, "file_sha256": files, "provenance": {"cv": "StratifiedGroupKFold on frozen v02 Development partition only", "group": "exact equality of four transformed features", "scaler_fit_scope": "inside each fold; MLP/AE scaler fit on inner training-only data", "ae_threshold": "Normal-only inner calibration with empirical FPR budget 0.01", "v02_artifacts_overwritten": False, "runtime_and_suricata_pipeline_changed": False}}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def run(output: str | Path = OUTPUT) -> Path:
    output = Path(output)
    if output.exists(): raise FileExistsError(f"v03 output already exists; refusing overwrite: {output}")
    data = preprocess_raw(TRAIN_FILE); X, partition = _load_v02_partition(data)
    staging = output.parent / (output.name + ".staging")
    if staging.exists(): shutil.rmtree(staging)
    staging.mkdir(parents=True); _write_reports(data, partition, staging); eda_figures = _save_eda_figures(data.processed, staging / "figures" / "eda")
    y = data.processed["label"].to_numpy(dtype=np.int8); oof, thresholds, fold_metrics, histories, checkpoints = _fit_and_score_cv(X, y, partition, staging)
    pd.DataFrame(fold_metrics).to_csv(staging / "cv_fold_metrics.csv", index=False)
    summary_rows = []
    for family in oof:
        rows = [row for row in fold_metrics if row["family"] == family]
        summary_rows.append({"family": family, **{f"{metric}_mean": float(np.mean([row[metric] for row in rows])) for metric in METRIC_NAMES}, **{f"{metric}_std": float(np.std([row[metric] for row in rows], ddof=1)) for metric in METRIC_NAMES}})
    pd.DataFrame(summary_rows).to_csv(staging / "cv_summary.csv", index=False); np.savez_compressed(staging / "cv_oof_scores.npz", labels=y[partition["development"]], **oof, **{f"threshold_{family}": values for family, values in thresholds.items()}); (staging / "training_history.json").write_text(json.dumps(histories, indent=2), encoding="utf-8")
    evaluation_figures = _save_evaluation_figures(y[partition["development"]], oof, thresholds, fold_metrics, histories, staging / "figures" / "evaluation"); (staging / "model_comparison.json").write_text(json.dumps(summary_rows, indent=2), encoding="utf-8")
    _write_hash_manifest(staging, data, partition, [f"figures/eda/{name}" for name in eda_figures] + [f"figures/evaluation/{name}" for name in evaluation_figures], checkpoints); staging.rename(output); return output


def write_blocked_report(output: str | Path = OUTPUT, reason: str | None = None) -> Path:
    output = Path(output)
    if output.exists(): raise FileExistsError(f"Cannot overwrite existing v03 output: {output}")
    output.mkdir(parents=True); reason = reason or f"Missing authorized raw dataset: {TRAIN_FILE}"
    (output / "BLOCKED.md").write_text("# UNSW v03 research completeness — BLOCKED\n\nNo EDA, preprocessing statistics, leakage numbers, CV metrics, model checkpoints or PNG research figures were generated because the authorized raw UNSW-NB15 training CSV is absent.\n\nReason: `" + reason + "`\n\nThe official test remains frozen and was not opened. Existing v02/G4/G5/runtime artifacts were not modified.\n", encoding="utf-8")
    (output / "manifest.json").write_text(json.dumps({"experiment": "unsw_v03_research_completeness", "status": "BLOCKED_MISSING_DATASET", "dataset": "UNSW-NB15", "raw_training_file": str(TRAIN_FILE), "official_test_accessed": False, "numbers_generated": False, "figures_generated": False, "cv_executed": False, "reason": reason}, indent=2), encoding="utf-8")
    (output / "provenance.json").write_text(json.dumps({"status": "BLOCKED", "raw_training_file": str(TRAIN_FILE), "official_test_accessed": False, "v02_artifacts_modified": False, "g4_g5_evidence_modified": False, "runtime_staging_modified": False, "production_suricata_pipeline_modified": False, "numbers_or_figures_generated": False}, indent=2), encoding="utf-8")
    return output


def verify(output: str | Path = OUTPUT) -> None:
    output = Path(output); manifest_path = output / "manifest.json"
    if not manifest_path.is_file(): raise FileNotFoundError(manifest_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("experiment") != "unsw_v03_research_completeness" or manifest.get("official_test_accessed") is not False: raise ValueError("Unexpected v03 experiment manifest")
    if manifest.get("status") == "BLOCKED_MISSING_DATASET":
        if manifest.get("numbers_generated") is not False or manifest.get("cv_executed") is not False or not (output / "BLOCKED.md").is_file(): raise ValueError("Invalid blocked report")
        print("BLOCKED REPORT VERIFIED: no numbers, CV or figures generated"); return
    if manifest.get("status") != "COMPLETED": raise ValueError("Unknown v03 status")
    required = ("preprocessing_report.json", "before_after_samples.csv", "class_distribution_before_after.csv", "quantiles_and_outliers.csv", "leakage_audit.json", "cv_fold_metrics.csv", "cv_summary.csv", "cv_oof_scores.npz", "training_history.json", "model_comparison.json")
    for filename in required:
        if not (output / filename).is_file(): raise ValueError(f"Missing v03 artifact: {filename}")
    folds = pd.read_csv(output / "cv_fold_metrics.csv")
    if len(folds) != FOLDS * 4 or set(folds["family"]) != set(_model_factories()): raise ValueError("CV fold metric contract mismatch")
    with np.load(output / "cv_oof_scores.npz", allow_pickle=False) as saved:
        labels = saved["labels"]
        for family in _model_factories():
            if saved[family].shape != labels.shape or saved[f"threshold_{family}"].shape != labels.shape: raise ValueError(f"OOF score shape mismatch: {family}")
    for filename, expected_hash in manifest.get("file_sha256", {}).items():
        path = output / filename
        if not path.is_file() or sha256(path) != expected_hash: raise ValueError(f"Artifact hash mismatch: {filename}")
    for figure in manifest.get("figures", []):
        path = output / figure
        if not path.is_file() or path.read_bytes()[:8] != b"\x89PNG\r\n\x1a\n": raise ValueError(f"Invalid PNG figure: {figure}")
    for checkpoint in manifest.get("checkpoints", []):
        if not (output / checkpoint).is_file(): raise ValueError(f"Missing checkpoint: {checkpoint}")
    print("PASS: UNSW V03 RESEARCH COMPLETENESS VERIFIED"); print("OFFICIAL TEST NOT ACCESSED")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--output", type=Path, default=OUTPUT); parser.add_argument("--blocked-report", action="store_true"); args = parser.parse_args(argv)
    try: path = run(args.output)
    except DatasetUnavailable as exc:
        if not args.blocked_report: print(f"BLOCKED: {exc}"); return 2
        path = write_blocked_report(args.output, str(exc)); print(f"BLOCKED: {path}"); return 2
    print(f"PASS: {path}"); print("OFFICIAL TEST NOT ACCESSED"); return 0


if __name__ == "__main__":
    raise SystemExit(main())
