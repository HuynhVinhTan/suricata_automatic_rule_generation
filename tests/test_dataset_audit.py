import csv
import json

from netids.dataset_audit import profile_csv


def _write_csv(path):
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(["feature", "label", "timestamp"])
        writer.writerow(["1", "Normal", "2026-01-01T00:00:00Z"])
        writer.writerow(["1", "Attack", "2026-01-01T00:00:01Z"])
        writer.writerow(["2", "Normal", "bad-time"])
        writer.writerow(["3", "Normal", "2026-01-01T00:00:03Z"])
        writer.writerow(["3", "Normal", "2026-01-01T00:00:03Z"])


def test_profile_csv_reports_quality_findings(tmp_path):
    path = tmp_path / "sample.csv"
    _write_csv(path)

    report = profile_csv(
        path,
        tmp_path / "audit",
        feature_columns=["feature"],
        label_columns=["label"],
        timestamp_columns=["timestamp"],
    )

    assert report["record_count"] == 5
    assert report["exact_duplicate_rows"] == 1
    assert report["contradictory_feature_labels"] == 1
    assert report["invalid_timestamps"] == 1
    assert report["label_distribution"] == {"Attack": 1, "Normal": 4}
    assert json.loads((tmp_path / "audit" / "profile.json").read_text()) == report


def test_profile_csv_rejects_duplicate_header_names(tmp_path):
    path = tmp_path / "duplicate-header.csv"
    path.write_text("a,a\n1,2\n", encoding="utf-8")

    report = profile_csv(path, tmp_path / "audit")

    assert report["duplicate_column_names"] == ["a"]
