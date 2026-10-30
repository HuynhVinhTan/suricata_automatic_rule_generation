"""CTU-13 dataset adapter.

Converts CTU-13 flow records into a candidate feature
contract shared with the ML training pipeline.

This module does not fit a scaler or train a model.
"""

import numpy as np
import pandas as pd

MODEL_FEATURES = (
    "protocol_tcp",
    "duration_log",
    "packets_log",
    "bytes_log",
)

REQUIRED_COLUMNS = (
    "StartTime",
    "SrcAddr",
    "DstAddr",
    "Proto",
    "Dur",
    "TotPkts",
    "TotBytes",
    "Label",
)


def prepare_ctu13_flows(
    raw: pd.DataFrame,
) -> pd.DataFrame:
    """Validate and transform CTU-13 TCP/UDP flows."""

    data = raw.copy()
    data.columns = data.columns.str.strip()

    missing = set(REQUIRED_COLUMNS) - set(data.columns)

    if missing:
        raise ValueError(
            f"Missing CTU-13 columns: {sorted(missing)}"
        )

    labels = data["Label"].astype("string").str.strip()

    flags = {
        "Background": labels.str.contains(
            "Background", case=False, regex=False, na=False
        ),
        "Normal": labels.str.contains(
            "Normal", case=False, regex=False, na=False
        ),
        "Botnet": labels.str.contains(
            "Botnet", case=False, regex=False, na=False
        ),
    }

    match_count = sum(flag.astype(int) for flag in flags.values())

    if not match_count.eq(1).all():
        raise ValueError(
            "CTU-13 contains ambiguous or unmatched labels."
        )

    protocol = data["Proto"].astype("string").str.lower()
    mask = protocol.isin(["tcp", "udp"])

    frame = data.loc[mask, list(REQUIRED_COLUMNS)].copy()

    frame["protocol"] = protocol.loc[mask]

    frame["label_group"] = "Unclassified"

    for name, flag in flags.items():
        frame.loc[flag.loc[mask], "label_group"] = name

    frame["target"] = pd.Series(
        pd.NA, index=frame.index, dtype="Int64"
    )

    frame.loc[frame["label_group"] == "Normal", "target"] = 0
    frame.loc[frame["label_group"] == "Botnet", "target"] = 1

    frame["timestamp"] = pd.to_datetime(
        frame["StartTime"], errors="coerce"
    )

    if frame["timestamp"].isna().any():
        raise ValueError("Invalid CTU-13 timestamps.")

    numeric_map = {
        "Dur": "duration_s",
        "TotPkts": "total_packets",
        "TotBytes": "total_bytes",
    }

    for original, renamed in numeric_map.items():
        frame[renamed] = pd.to_numeric(
            frame[original], errors="coerce"
        )

    numeric = frame[list(numeric_map.values())]

    if not np.isfinite(numeric.to_numpy(dtype=float)).all():
        raise ValueError("Non-finite CTU-13 features.")

    if (numeric < 0).any().any():
        raise ValueError("Negative CTU-13 features.")

    frame["protocol_tcp"] = (
        frame["protocol"] == "tcp"
    ).astype(int)

    frame["duration_log"] = np.log1p(frame["duration_s"])
    frame["packets_log"] = np.log1p(frame["total_packets"])
    frame["bytes_log"] = np.log1p(frame["total_bytes"])

    return frame[
        [
            "timestamp",
            "SrcAddr",
            "DstAddr",
            "protocol",
            "label_group",
            "target",
            "duration_s",
            "total_packets",
            "total_bytes",
            *MODEL_FEATURES,
        ]
    ].reset_index(drop=True)
