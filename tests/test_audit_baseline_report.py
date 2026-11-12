import json

from scripts.audit_baseline_report import audit_report


def test_audit_report_rejects_missing_eve_hash(tmp_path):
    case = {
        "case_id": "attack-01",
        "label": "Attack",
        "pcap_sha256": "c" * 64,
        "baseline": {"evidence": {"eve_sha256": "d" * 64}},
        "augmented": {"evidence": {"eve_sha256": "e" * 64}},
    }
    report = {
        "run_id": "audit-run",
        "config_sha256": "a" * 64,
        "baseline_rules_sha256": "b" * 64,
        "reconnaissance_sids": [9103003],
        "ruleset_provenance": "NEW_VM1_COPY_2026-11-12",
        "cases": [dict(case, case_id=f"attack-{i:02d}") for i in range(1, 7)],
    }
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    try:
        audit_report(path, tmp_path / "missing-eve")
    except ValueError as exc:
        assert "EVE" in str(exc)
    else:
        raise AssertionError("missing EVE must fail closed")
