"""Read-only audit of a private baseline comparison report and its EVE hashes."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _eve_path(eve_root: Path, case_id: str, arm: str) -> Path:
    path = eve_root / case_id / arm / "eve.json"
    if not path.is_file() or path.stat().st_size == 0:
        raise ValueError(f"missing or empty EVE for {case_id}/{arm}: {path}")
    return path


def audit_report(report_path: Path, eve_root: Path, recon_sids_path: Path | None = None) -> dict:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    cases = report.get("cases")
    if not isinstance(cases, list) or len(cases) != 6:
        raise ValueError("audit requires exactly six report cases")
    if report.get("ruleset_provenance") != "NEW_VM1_COPY_2026-11-12":
        raise ValueError("unexpected or historical ruleset provenance")
    summary = []
    for case in cases:
        case_id = case["case_id"]
        row = {"case_id": case_id, "label": case["label"], "pcap_sha256": case["pcap_sha256"], "arms": {}}
        for arm in ("baseline", "augmented"):
            expected = case[arm]["evidence"]["eve_sha256"]
            path = _eve_path(eve_root, case_id, arm)
            actual = _sha256(path)
            if actual != expected:
                raise ValueError(f"EVE SHA-256 mismatch for {case_id}/{arm}")
            event_types = case[arm]["evidence"]["event_types"]
            row["arms"][arm] = {
                "eve_sha256": actual,
                "event_count": case[arm]["evidence"]["event_count"],
                "alert_events": case[arm]["evidence"]["alert_events"],
                "reconnaissance_alert_events": case[arm]["evidence"]["reconnaissance_alert_events"],
                "event_types": event_types,
            }
        summary.append(row)
    recon_hash = None
    if recon_sids_path is not None:
        if not recon_sids_path.is_file() or recon_sids_path.stat().st_size == 0:
            raise ValueError("missing or empty reconnaissance allow-list")
        recon_hash = _sha256(recon_sids_path)
    return {
        "schema_version": "baseline_audit_summary_v1",
        "run_id": report["run_id"],
        "ruleset_provenance": report["ruleset_provenance"],
        "config_sha256": report["config_sha256"],
        "baseline_rules_sha256": report["baseline_rules_sha256"],
        "recon_allowlist_sha256": recon_hash,
        "cases": summary,
        "session_metrics": report["session_metrics"],
        "verification": "EVE files independently rehashed; raw PCAPs and credentials are not included",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--eve-root", type=Path, required=True)
    parser.add_argument("--recon-sids", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = audit_report(args.report, args.eve_root, args.recon_sids)
        args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        print(json.dumps(result["session_metrics"], sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"FAIL CLOSED: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
