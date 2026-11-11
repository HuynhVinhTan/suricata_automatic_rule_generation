"""Streaming, read-only quality profiling for delimited network datasets."""

from __future__ import annotations

import csv
import hashlib
import json
import math
import shutil
import sqlite3
from collections import Counter
from datetime import datetime
from pathlib import Path


def _json_hash(value) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=False).encode()
    ).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _timestamp_valid(value: str) -> bool:
    if not value:
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        return True
    except ValueError:
        for pattern in ("%Y/%m/%d %H:%M:%S.%f", "%Y/%m/%d %H:%M:%S"):
            try:
                datetime.strptime(value, pattern)
                return True
            except ValueError:
                pass
        try:
            number = float(value)
            return math.isfinite(number)
        except ValueError:
            return False


def profile_csv(
    path: Path,
    output_dir: Path,
    *,
    feature_columns=(),
    label_columns=(),
    timestamp_columns=(),
) -> dict:
    """Profile one CSV without loading rows into memory or modifying the source."""
    path = Path(path).resolve(strict=True)
    if not path.is_file() or path.is_symlink():
        raise ValueError("Dataset must be a regular file")
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    if shutil.disk_usage(output_dir).free < max(64 * 1024 * 1024, path.stat().st_size):
        raise OSError("Insufficient disk space for audit SQLite database")

    feature_columns = tuple(feature_columns)
    label_columns = tuple(label_columns)
    timestamp_columns = tuple(timestamp_columns)
    db_path = output_dir / "quality.sqlite3"
    labels = Counter()
    feature_stats = {}
    missing_values = Counter()
    malformed_rows = 0
    invalid_timestamps = 0
    rows = 0
    duplicate_column_names = []
    with sqlite3.connect(db_path) as db:
        db.execute("CREATE TABLE row_hashes (hash TEXT PRIMARY KEY, count INTEGER NOT NULL)")
        db.execute(
            "CREATE TABLE feature_labels (feature_hash TEXT NOT NULL, label TEXT NOT NULL, "
            "PRIMARY KEY(feature_hash, label))"
        )
        with path.open("r", encoding="utf-8", newline="", errors="replace") as stream:
            reader = csv.reader(stream)
            try:
                header = [name.strip() for name in next(reader)]
            except StopIteration:
                header = []
            seen = set()
            duplicate_column_names = sorted({name for name in header if name in seen or seen.add(name)})
            indexes = {name: i for i, name in enumerate(header)}
            for name in feature_columns + label_columns + timestamp_columns:
                if name not in indexes:
                    raise ValueError(f"Column not found: {name}")
            for values in reader:
                if len(values) != len(header):
                    malformed_rows += 1
                    continue
                rows += 1
                row = dict(zip(header, values))
                row_hash = _json_hash(values)
                db.execute(
                    "INSERT INTO row_hashes(hash,count) VALUES(?,1) "
                    "ON CONFLICT(hash) DO UPDATE SET count=count+1",
                    (row_hash,),
                )
                label = "|".join(row[name].strip() for name in label_columns) if label_columns else ""
                if label:
                    labels[label] += 1
                feature = tuple(row[name].strip() for name in feature_columns)
                if feature_columns:
                    db.execute(
                        "INSERT OR IGNORE INTO feature_labels(feature_hash,label) VALUES(?,?)",
                        (_json_hash(feature), label),
                    )
                for name, value in row.items():
                    if value.strip() == "":
                        missing_values[name] += 1
                for name in feature_columns:
                    value = row[name].strip()
                    stat = feature_stats.setdefault(name, {"numeric": 0, "nan": 0, "inf": 0, "min": None, "max": None})
                    try:
                        number = float(value)
                        if math.isnan(number):
                            stat["nan"] += 1
                        elif math.isinf(number):
                            stat["inf"] += 1
                        else:
                            stat["numeric"] += 1
                            stat["min"] = number if stat["min"] is None else min(stat["min"], number)
                            stat["max"] = number if stat["max"] is None else max(stat["max"], number)
                    except ValueError:
                        pass
                for name in timestamp_columns:
                    if not _timestamp_valid(row[name].strip()):
                        invalid_timestamps += 1
        duplicate_rows = db.execute("SELECT COALESCE(SUM(count - 1), 0) FROM row_hashes").fetchone()[0]
        contradictory = db.execute(
            "SELECT COUNT(*) FROM (SELECT feature_hash FROM feature_labels "
            "GROUP BY feature_hash HAVING COUNT(*) > 1)"
        ).fetchone()[0]
        db.commit()
    report = {
        "path": str(path),
        "sha256": _sha256_file(path),
        "size_bytes": path.stat().st_size,
        "record_count": rows,
        "column_count": len(header),
        "columns": header,
        "duplicate_column_names": duplicate_column_names,
        "malformed_rows": malformed_rows,
        "missing_values": dict(sorted(missing_values.items())),
        "nan_or_inf": {name: value for name, value in feature_stats.items() if value["nan"] or value["inf"]},
        "exact_duplicate_rows": int(duplicate_rows),
        "contradictory_feature_labels": int(contradictory),
        "label_distribution": dict(sorted(labels.items())),
        "feature_stats": feature_stats,
        "invalid_timestamps": invalid_timestamps,
        "timestamp_columns": list(timestamp_columns),
        "host_identity_columns": [name for name in header if any(token in name.lower() for token in ("ip", "host", "src", "dst"))],
        "feature_columns": list(feature_columns),
        "label_columns": list(label_columns),
    }
    (output_dir / "profile.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report
