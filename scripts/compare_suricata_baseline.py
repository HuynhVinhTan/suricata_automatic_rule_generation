"""Fail-closed paired baseline/augmented Suricata replay experiment."""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,100}$")
SID_RE = re.compile(r"\bsid\s*:\s*(\d+)\s*;", re.IGNORECASE)


class ExperimentError(RuntimeError):
    pass


def _validate_hash(value: str, field: str) -> str:
    if not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise ExperimentError(f"{field} must be a 64-character SHA-256 hex digest")
    return value.lower()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_rule_sha256(path: Path) -> str:
    data = path.read_bytes()
    if not data.endswith(b"\n") or data.endswith(b"\n\n") or b"\r" in data:
        raise ExperimentError("candidate rule must contain exactly one terminal LF")
    return hashlib.sha256(data[:-1]).hexdigest()


def active_rule_sids(path: Path) -> set[int]:
    sids: set[int] = set()
    for raw in path.read_text(encoding="utf-8", errors="strict").splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        match = SID_RE.search(raw)
        if match:
            sids.add(int(match.group(1)))
    if not sids:
        raise ExperimentError(f"ruleset has no active SID rules: {path}")
    return sids


def _validate_id(value: str, field: str) -> str:
    if not SAFE_ID.fullmatch(value):
        raise ExperimentError(f"invalid non-traversing {field}: {value!r}")
    return value


@dataclass(frozen=True)
class Case:
    case_id: str
    label: str
    pcap: Path
    expected_sha256: str


def parse_eve(path: Path, recon_sids: set[int], recon_signatures: set[str]) -> dict:
    """Require fresh, non-empty, valid EVE evidence."""
    if not path.is_file() or path.stat().st_size == 0:
        raise ExperimentError(f"missing or empty EVE evidence: {path}")
    total = 0
    alerts = Counter()
    recon = 0
    event_types = Counter()
    with path.open("r", encoding="utf-8", errors="strict") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ExperimentError(f"invalid EVE JSON at {path}:{line_number}") from exc
            if not isinstance(event, dict) or not isinstance(event.get("event_type"), str):
                raise ExperimentError(f"malformed EVE event at {path}:{line_number}")
            total += 1
            event_types[event["event_type"]] += 1
            if event["event_type"] != "alert":
                continue
            alert = event.get("alert")
            if not isinstance(alert, dict):
                raise ExperimentError(f"malformed alert event at {path}:{line_number}")
            try:
                sid = int(alert["signature_id"])
            except (KeyError, TypeError, ValueError) as exc:
                raise ExperimentError(f"alert lacks integer signature_id at {path}:{line_number}") from exc
            signature = str(alert.get("signature", ""))
            alerts[f"{sid}:{signature}"] += 1
            if sid in recon_sids or signature in recon_signatures:
                recon += 1
    if total == 0:
        raise ExperimentError(f"EVE contains no events: {path}")
    return {
        "eve_sha256": sha256(path),
        "event_count": total,
        "event_types": dict(event_types),
        "alert_events": sum(alerts.values()),
        "reconnaissance_alert_events": recon,
        "reconnaissance_detected": recon > 0,
        "signatures": dict(alerts),
    }


def _run_checked(command: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, capture_output=True, text=True, check=False, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise ExperimentError(f"command timed out after {timeout}s: {' '.join(command)}") from exc


def syntax_check(suricata: str, config: Path, rules: Path, output: Path, timeout: int) -> dict:
    output.mkdir()
    result = _run_checked([suricata, "-T", "--init-errors-fatal", "-c", str(config), "-S", str(rules), "-l", str(output)], timeout=timeout)
    (output / "stdout.txt").write_text(result.stdout, encoding="utf-8", newline="\n")
    (output / "stderr.txt").write_text(result.stderr, encoding="utf-8", newline="\n")
    if result.returncode != 0:
        raise ExperimentError(f"Suricata syntax/ruleset preflight failed for {rules}")
    return {"returncode": result.returncode, "stdout_sha256": sha256(output / "stdout.txt"), "stderr_sha256": sha256(output / "stderr.txt"), "active_sid_count": len(active_rule_sids(rules))}


def replay(suricata: str, config: Path, rules: Path, pcap: Path, output: Path, timeout: int, recon_sids: set[int], recon_signatures: set[str]) -> dict:
    if output.exists():
        raise ExperimentError(f"refusing to reuse replay directory: {output}")
    output.mkdir(parents=True)
    started = time.perf_counter_ns()
    result = _run_checked([suricata, "-c", str(config), "-S", str(rules), "-r", str(pcap), "-l", str(output), "--runmode", "single"], timeout=timeout)
    elapsed_ms = round((time.perf_counter_ns() - started) / 1_000_000, 3)
    (output / "stdout.txt").write_text(result.stdout, encoding="utf-8", newline="\n")
    (output / "stderr.txt").write_text(result.stderr, encoding="utf-8", newline="\n")
    if result.returncode != 0:
        raise ExperimentError(f"Suricata replay failed for {pcap}: returncode={result.returncode}")
    eve = output / "eve.json"
    evidence = parse_eve(eve, recon_sids, recon_signatures)
    return {"returncode": result.returncode, "elapsed_ms": elapsed_ms, "stdout_sha256": sha256(output / "stdout.txt"), "stderr_sha256": sha256(output / "stderr.txt"), "eve_path": str(eve), "evidence": evidence}


def metrics(rows: list[dict], arm: str) -> dict:
    tp = fp = fn = tn = 0
    for row in rows:
        actual = row["label"] == "Attack"
        predicted = row[arm]["evidence"]["reconnaissance_detected"]
        if actual and predicted: tp += 1
        elif not actual and predicted: fp += 1
        elif actual and not predicted: fn += 1
        else: tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {"TP": tp, "FP": fp, "FN": fn, "TN": tn, "Precision": precision, "Recall": recall, "F1": f1, "FPR": fpr}


def load_recon_sids(path: Path) -> set[int]:
    if not path.is_file() or path.stat().st_size == 0:
        raise ExperimentError(f"missing or empty reconnaissance SID manifest: {path}")
    values = {int(line.strip()) for line in path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.lstrip().startswith("#")}
    if not values:
        raise ExperimentError("reconnaissance SID manifest has no SIDs")
    return values


def _exclusive_write(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
    except Exception:
        try: path.unlink()
        except FileNotFoundError: pass
        raise


def run_experiment(*, suricata: str, config: Path, expected_config_sha256: str, baseline_rules: Path, expected_baseline_sha256: str, candidate_rule: Path, expected_candidate_rule_sha256: str, cases: list[Case], output_root: Path, run_id: str, recon_sids: set[int], recon_signatures: set[str], timeout: int) -> dict:
    if len(cases) != 6 or sum(case.label == "Attack" for case in cases) != 3 or sum(case.label == "Normal" for case in cases) != 3:
        raise ExperimentError("exactly six cases (three Attack and three Normal) are required")
    if len({case.case_id for case in cases}) != 6:
        raise ExperimentError("case IDs must be unique")
    _validate_id(run_id, "run_id")
    if output_root.exists():
        raise ExperimentError(f"output root already exists; use a new exclusive run: {output_root}")
    _validate_hash(expected_config_sha256, "expected configuration SHA-256")
    _validate_hash(expected_baseline_sha256, "expected baseline SHA-256")
    _validate_hash(expected_candidate_rule_sha256, "expected candidate SHA-256")
    if sha256(config) != expected_config_sha256:
        raise ExperimentError("configuration SHA-256 mismatch")
    if sha256(baseline_rules) != expected_baseline_sha256:
        raise ExperimentError("baseline rules SHA-256 mismatch")
    if canonical_rule_sha256(candidate_rule) != expected_candidate_rule_sha256:
        raise ExperimentError("candidate canonical rule SHA-256 mismatch")
    candidate_sids = active_rule_sids(candidate_rule)
    baseline_sids = active_rule_sids(baseline_rules)
    if len(candidate_sids) != 1 or baseline_sids & candidate_sids:
        raise ExperimentError("candidate must have one SID not present in baseline")
    for case in cases:
        _validate_id(case.case_id, "case_id")
        if case.label not in {"Attack", "Normal"}:
            raise ExperimentError(f"invalid ground-truth label: {case.label}")
        _validate_hash(case.expected_sha256, f"{case.case_id} expected PCAP SHA-256")
        if not case.pcap.is_file() or sha256(case.pcap) != case.expected_sha256.lower():
            raise ExperimentError(f"PCAP missing or SHA-256 mismatch: {case.case_id}")
    output_root.mkdir(parents=True)
    baseline_path = output_root / "baseline.rules"
    augmented_path = output_root / "augmented.rules"
    _exclusive_write(baseline_path, baseline_rules.read_bytes())
    _exclusive_write(augmented_path, baseline_rules.read_bytes() + candidate_rule.read_bytes())
    if active_rule_sids(augmented_path) != baseline_sids | candidate_sids:
        raise ExperimentError("augmented effective SID set is not exactly baseline union candidate")
    syntax = {"baseline": syntax_check(suricata, config, baseline_path, output_root / "syntax-baseline", timeout), "augmented": syntax_check(suricata, config, augmented_path, output_root / "syntax-augmented", timeout)}
    rows = []
    for case in cases:
        row = {"case_id": case.case_id, "label": case.label, "pcap": str(case.pcap), "pcap_sha256": case.expected_sha256}
        row["baseline"] = replay(suricata, config, baseline_path, case.pcap, output_root / case.case_id / "baseline", timeout, recon_sids, recon_signatures)
        row["augmented"] = replay(suricata, config, augmented_path, case.pcap, output_root / case.case_id / "augmented", timeout, recon_sids, recon_signatures)
        rows.append(row)
    report = {"schema_version": "suricata_baseline_comparison_v2", "run_id": run_id, "ruleset_provenance": "NEW_VM1_COPY_2026-11-12", "historical_ruleset_reconstruction": False, "definition": "reconnaissance_detected iff an alert SID or exact signature is in the precommitted allow-list", "generic_alerts_are_not_reconnaissance": True, "config_sha256": expected_config_sha256, "baseline_rules_sha256": expected_baseline_sha256, "candidate_rule_sha256": expected_candidate_rule_sha256, "baseline_active_sid_count": len(baseline_sids), "augmented_active_sid_count": len(baseline_sids | candidate_sids), "reconnaissance_sids": sorted(recon_sids), "reconnaissance_signatures": sorted(recon_signatures), "syntax": syntax, "cases": rows, "session_metrics": {"baseline": metrics(rows, "baseline"), "augmented": metrics(rows, "augmented")}}
    _exclusive_write(output_root / "report.json", (json.dumps(report, indent=2, sort_keys=True) + "\n").encode())
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--suricata", default="suricata")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--expected-config-sha256", required=True)
    parser.add_argument("--baseline-rules", type=Path, required=True)
    parser.add_argument("--expected-baseline-sha256", required=True)
    parser.add_argument("--candidate-rule", type=Path, required=True)
    parser.add_argument("--expected-candidate-rule-sha256", required=True)
    parser.add_argument("--case", action="append", nargs=3, metavar=("ID", "LABEL", "PCAP|SHA256"), required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--recon-sid", action="append", type=int, default=[])
    parser.add_argument("--recon-sids-file", type=Path)
    parser.add_argument("--recon-signature", action="append", default=[])
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()
    try:
        cases = []
        for case_id, label, packed in args.case:
            delimiter = "|" if "|" in packed else "#"
            pcap_text, expected_hash = packed.rsplit(delimiter, 1)
            cases.append(Case(case_id, label, Path(pcap_text), expected_hash))
        recon_sids = set(args.recon_sid)
        if args.recon_sids_file:
            recon_sids.update(load_recon_sids(args.recon_sids_file))
        if not recon_sids and not args.recon_signature:
            raise ExperimentError("a precommitted reconnaissance SID/signature allow-list is required")
        report = run_experiment(suricata=args.suricata, config=args.config, expected_config_sha256=args.expected_config_sha256, baseline_rules=args.baseline_rules, expected_baseline_sha256=args.expected_baseline_sha256, candidate_rule=args.candidate_rule, expected_candidate_rule_sha256=args.expected_candidate_rule_sha256, cases=cases, output_root=args.output_root, run_id=args.run_id, recon_sids=recon_sids, recon_signatures=set(args.recon_signature), timeout=args.timeout)
        print(json.dumps(report["session_metrics"], indent=2, sort_keys=True))
        return 0
    except (ExperimentError, OSError, ValueError) as exc:
        print(f"FAIL CLOSED: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
