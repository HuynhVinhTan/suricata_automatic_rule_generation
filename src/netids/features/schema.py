"""Validation contract for experimental flow features.

Schema version: flow_features_v0.1
This schema is validated on CTU-13, not yet certified
as semantically equivalent to Suricata EVE.
"""

import numpy as np
import pandas as pd

SCHEMA_VERSION = "flow_features_v0.1"

FEATURE_COLUMNS = (
    "protocol_tcp",
    "duration_log",
    "packets_log",
    "bytes_log",
)

LABEL_VALUES = {
    "Normal": 0,
    "Botnet": 1,
    "Background": None,
}


def validate_feature_matrix(
    frame: pd.DataFrame,
) -> pd.DataFrame:
    """Validate and return features in canonical order.

    Extra metadata columns are allowed but excluded.
    No imputation, scaling or data modification.
    """

    if not isinstance(frame, pd.DataFrame):
        raise TypeError("Expected a pandas DataFrame.")

    if not frame.columns.is_unique:
        raise ValueError("Duplicate feature columns.")

    missing = [
        name for name in FEATURE_COLUMNS
        if name not in frame.columns
    ]

    if missing:
        raise ValueError(f"Missing features: {missing}")

    X = frame.loc[:, list(FEATURE_COLUMNS)].copy()

    for name in FEATURE_COLUMNS:
        if not pd.api.types.is_numeric_dtype(X[name]):
            raise ValueError(f"Non-numeric feature: {name}")

        values = X[name].to_numpy(dtype=float)

        if not np.isfinite(values).all():
            raise ValueError(
                f"Missing or non-finite values: {name}"
            )

        if (values < 0).any():
            raise ValueError(f"Negative feature: {name}")

    if not X["protocol_tcp"].isin([0, 1]).all():
        raise ValueError(
            "protocol_tcp must contain only 0 or 1."
        )

    return X


def validate_ctu_labels(
    frame: pd.DataFrame,
) -> None:
    """Validate CTU label groups and binary targets."""

    required = {"label_group", "target"}

    if not required.issubset(frame.columns):
        raise ValueError("Missing label metadata.")

    if frame["label_group"].isna().any():
        raise ValueError("Missing label group.")

    unknown = set(frame["label_group"]) - set(LABEL_VALUES)

    if unknown:
        raise ValueError(f"Unknown label groups: {unknown}")

    for group, expected in LABEL_VALUES.items():
        values = frame.loc[
            frame["label_group"] == group, "target"
        ]

        if expected is None:
            valid = values.isna().all()
        else:
            valid = values.notna().all() and (
                values == expected
            ).all()

        if not valid:
            raise ValueError(
                f"Inconsistent target for {group}"
            )
