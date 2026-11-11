import csv
import json
import pytest

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


def test_duplicate_columns_report_equal_and_unequal_values(tmp_path):
    path = tmp_path / "duplicate-header.csv"
    path.write_text("a,a,label\n1,1,N\n1,2,A\n", encoding="utf-8")

    report = profile_csv(path, tmp_path / "audit")

    assert report["duplicate_column_values"]["a"] == {"equal": 1, "unequal": 1}


def test_profile_removes_temporary_sqlite_on_success_and_failure(tmp_path):
    path = tmp_path / "sample.csv"
    path.write_text("a\n1\n", encoding="utf-8")
    output = tmp_path / "audit"
    profile_csv(path, output)
    assert not list(output.glob("*.sqlite3"))

    with pytest.raises(ValueError):
        profile_csv(path, tmp_path / "bad", feature_columns=["missing"])
    assert not list((tmp_path / "bad").glob("*.sqlite3"))


def test_profile_rejects_invalid_utf8_without_replacing_bytes(tmp_path):
    path = tmp_path / "invalid.csv"
    path.write_bytes(b"a\n\xff\n")

    with pytest.raises(UnicodeDecodeError):
        profile_csv(path, tmp_path / "audit")


def test_profile_reports_partial_when_exact_checks_do_not_fit(tmp_path, monkeypatch):
    path = tmp_path / "sample.csv"
    path.write_text("a,label\n1,N\n2,A\n", encoding="utf-8")
    monkeypatch.setattr("netids.dataset_audit.shutil.disk_usage", lambda _: type("U", (), {"free": 0})())

    report = profile_csv(path, tmp_path / "audit", feature_columns=["a"], label_columns=["label"])

    assert report["audit_status"] == "PARTIAL"
    assert report["exact_duplicate_rows"] is None
    assert report["record_count"] == 2


def test_profile_counts_malformed_rows_without_changing_source(tmp_path):
    path = tmp_path / "malformed.csv"
    path.write_text("a,b\n1,2\nmalformed\n", encoding="utf-8")
    report = profile_csv(path, tmp_path / "audit")
    assert report["malformed_rows"] == 1
    assert report["record_count"] == 1
