"""Chronological splitting with overlapping training flows removed."""

import numpy as np
import pandas as pd


def purged_chronological_split(
    frame: pd.DataFrame,
    train_fraction: float = 0.70,
):
    """
    Split flows chronologically.

    A training flow is retained only if:
      - its StartTime is strictly before the Test boundary
      - its EndTime is at or before the Test boundary

    Does not modify the original DataFrame.
    """

    if not 0 < train_fraction < 1:
        raise ValueError("train_fraction must be between 0 and 1.")

    required = {"timestamp", "duration_s"}

    if not required.issubset(frame.columns):
        raise ValueError("Missing temporal feature columns.")

    if len(frame) < 2:
        raise ValueError("At least two flows are required.")

    data = frame.copy()

    data["timestamp"] = pd.to_datetime(
        data["timestamp"], errors="coerce"
    )

    data["duration_s"] = pd.to_numeric(
        data["duration_s"], errors="coerce"
    ).astype(float)

    if data["timestamp"].isna().any():
        raise ValueError("Invalid timestamps.")

    duration = data["duration_s"].to_numpy()

    if not np.isfinite(duration).all():
        raise ValueError("Invalid flow durations.")

    if (duration < 0).any():
        raise ValueError("Negative flow durations.")

    data = data.sort_values(
        "timestamp", kind="mergesort"
    )

    split_idx = int(len(data) * train_fraction)

    if split_idx < 1 or split_idx >= len(data):
        raise ValueError("Invalid split size.")

    candidate_train = data.iloc[:split_idx].copy()
    test = data.iloc[split_idx:].copy()

    boundary = test["timestamp"].min()

    train_end = (
        candidate_train["timestamp"]
        + pd.to_timedelta(
            candidate_train["duration_s"],
            unit="s",
        )
    )

    if train_end.isna().any():
        raise ValueError("Invalid computed end timestamps.")

    crossing = train_end > boundary

    # Also remove same-start-time boundary ties
    tied = candidate_train["timestamp"] >= boundary

    keep = ~(crossing | tied)

    train = candidate_train.loc[keep].copy()

    if train.empty:
        raise ValueError("No training flows remain after purging.")

    report = {
        "boundary": boundary,
        "original_train": len(candidate_train),
        "purged_train": len(train),
        "test": len(test),
        "overlap_removed": int(crossing.sum()),
        "total_removed": int((~keep).sum()),
    }

    return train, test, report