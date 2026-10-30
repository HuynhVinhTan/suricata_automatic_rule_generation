"""UNSW-NB15 flow adapter. No training or inference."""

from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd


FEATURES = (
    "protocol_tcp",
    "duration_log",
    "packets_log",
    "bytes_log",
)

REQUIRED = (
    "dur",
    "proto",
    "spkts",
    "dpkts",
    "sbytes",
    "dbytes",
    "label",
)


@dataclass(frozen=True)
class UNSWData:
    X: np.ndarray
    y: np.ndarray
    source_row_indices: np.ndarray
    attack_categories: np.ndarray
    original_rows: int
    included_rows: int
    excluded_protocol_rows: int


def load_unsw_csv(path: str | Path) -> UNSWData:
    """Load labeled UNSW data into the four-feature flow contract.

    Supported protocols: TCP and UDP.
    Binary target: 0=Normal, 1=Attack.

    This adapter does not fit a scaler, train a model,
    modify the raw dataset, or perform inference.
    """

    path = Path(path)

    if not path.is_file():
        raise FileNotFoundError(path)

    fields = set(REQUIRED) | {"attack_cat"}

    table = pd.read_csv(
        path,
        usecols=lambda name: name in fields,
        low_memory=False,
    )

    missing = set(REQUIRED) - set(table.columns)

    if missing:
        raise ValueError(
            f"Missing UNSW columns: {sorted(missing)}"
        )

    if table.empty:
        raise ValueError("Empty UNSW file")

    labels = pd.to_numeric(
        table["label"],
        errors="coerce",
    )

    if (
        labels.isna().any()
        or not labels.isin([0, 1]).all()
    ):
        raise ValueError(
            "Invalid UNSW binary label; expected only 0 or 1"
        )

    protocols = (
        table["proto"]
        .astype("string")
        .str.strip()
        .str.lower()
    )

    accepted_mask = protocols.isin(
        ["tcp", "udp"]
    ).to_numpy(dtype=bool)

    indices = np.flatnonzero(accepted_mask)

    if len(indices) == 0:
        raise ValueError(
            "No supported TCP/UDP flows"
        )

    numeric_columns = [
        "dur",
        "spkts",
        "dpkts",
        "sbytes",
        "dbytes",
    ]

    raw = (
        table.iloc[indices][numeric_columns]
        .apply(pd.to_numeric, errors="coerce")
        .to_numpy(dtype=np.float64)
    )

    if (
        not np.isfinite(raw).all()
        or (raw < 0).any()
    ):
        raise ValueError(
            "Non-finite or negative UNSW flow value"
        )

    packets = raw[:, 1] + raw[:, 2]

    bytes_total = raw[:, 3] + raw[:, 4]

    X = np.column_stack(
        (
            (
                protocols.iloc[indices] == "tcp"
            ).to_numpy(dtype=np.float64),

            np.log1p(raw[:, 0]),

            np.log1p(packets),

            np.log1p(bytes_total),
        )
    )

    if not np.isfinite(X).all():
        raise ValueError(
            "Non-finite derived UNSW feature"
        )

    if "attack_cat" in table.columns:
        categories = (
            table["attack_cat"]
            .iloc[indices]
            .fillna("UNKNOWN")
            .astype(str)
            .to_numpy()
        )
    else:
        categories = np.full(
            len(indices),
            "UNKNOWN",
            dtype=object,
        )

    return UNSWData(
        X=X,
        y=labels.iloc[indices].to_numpy(
            dtype=np.int8
        ),
        source_row_indices=indices.astype(
            np.int64
        ),
        attack_categories=categories,
        original_rows=len(table),
        included_rows=len(indices),
        excluded_protocol_rows=(
            len(table) - len(indices)
        ),
    )