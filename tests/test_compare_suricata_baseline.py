import json
from pathlib import Path

import pytest

from scripts.compare_suricata_baseline import (
    Case,
    ExperimentError,
    metrics,
    parse_eve,
    run_experiment,
)


def _eve(path: Path, events):
    path.write_text("".join(json.dumps(event) + "\n" for event in events), encoding="utf-8")


def test_parse_eve_rejects_missing_empty_invalid_and_eventless(tmp_path):
    with pytest.raises(ExperimentError, match="missing or empty"):
        parse_eve(tmp_path / "missing.json", {9103003}, set())
    empty = tmp_path / "empty.json"
    empty.write_text("", encoding="utf-8")
    with pytest.raises(ExperimentError, match="missing or empty"):
        parse_eve(empty, {9103003}, set())
    invalid = tmp_path / "invalid.json"
    invalid.write_text("not-json\n", encoding="utf-8")
    with pytest.raises(ExperimentError, match="invalid EVE"):
        parse_eve(invalid, {9103003}, set())


def test_parse_eve_accepts_traffic_without_recon_and_counts_signature(tmp_path):
    eve = tmp_path / "eve.json"
    _eve(eve, [{"event_type": "flow"}, {"event_type": "alert", "alert": {"signature_id": 123, "signature": "generic"}}])
    result = parse_eve(eve, {9103003}, set())
    assert result["event_count"] == 2
    assert result["reconnaissance_detected"] is False
    assert result["alert_events"] == 1


def test_metrics_are_session_level():
    rows = [
        {"label": "Attack", "baseline": {"evidence": {"reconnaissance_detected": False}}, "augmented": {"evidence": {"reconnaissance_detected": True}}},
        {"label": "Normal", "baseline": {"evidence": {"reconnaissance_detected": False}}, "augmented": {"evidence": {"reconnaissance_detected": False}}},
    ]
    assert metrics(rows, "augmented") == {"TP": 1, "FP": 0, "FN": 0, "TN": 1, "Precision": 1.0, "Recall": 1.0, "F1": 1.0, "FPR": 0.0}


def test_run_requires_six_labels_and_pinned_inputs(tmp_path):
    rule = tmp_path / "candidate.rules"
    rule.write_text('alert tcp any any -> any any (sid:9103003; rev:1;)\n', encoding="utf-8")
    baseline = tmp_path / "baseline.rules"
    baseline.write_text('alert tcp any any -> any any (sid:1; rev:1;)\n', encoding="utf-8")
    config = tmp_path / "suricata.yaml"
    config.write_text("config\n", encoding="utf-8")
    with pytest.raises(ExperimentError, match="exactly six"):
        run_experiment(
            suricata="missing-suricata", config=config, expected_config_sha256="0" * 64,
            baseline_rules=baseline, expected_baseline_sha256="0" * 64,
            candidate_rule=rule, expected_candidate_rule_sha256="0" * 64,
            cases=[Case("attack-1", "Attack", config, "0" * 64)], output_root=tmp_path / "run",
            run_id="test", recon_sids={9103003}, recon_signatures=set(), timeout=1,
        )


def test_invalid_hash_is_rejected_before_execution(tmp_path):
    with pytest.raises(ExperimentError, match="SHA-256"):
        from scripts.compare_suricata_baseline import _validate_hash
        _validate_hash("not-a-hash", "input")
