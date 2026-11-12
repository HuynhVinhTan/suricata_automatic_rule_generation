"""Trusted, candidate-aware Suricata replay attestation.

This path is deliberately separate from the documented SID 9103003 recovery
signer. It signs only after revalidating the immutable candidate artifacts,
running Suricata syntax validation and replaying every independently pinned
Attack/Normal PCAP into a fresh exclusive output directory.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from pathlib import PurePosixPath

from netids.candidate_record import (
    APPROVED_CASE_MANIFEST_SHA256,
    APPROVED_INDEPENDENT_CASES,
    CandidateRecordError,
    build_candidate_record,
    verify_candidate_record,
    verify_signed_replay_evidence,
)
from netids.key_pins import require_pinned_replay_key
from netids.lifecycle_ed25519 import sha256_file, sign_record
from netids.trusted_replay import _config_safe


class CandidateReplayError(ValueError):
    pass


_HEX = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_THRESHOLD = re.compile(r"detection_filter\s*:\s*track\s+by_src\s*,\s*count\s+(\d+)\s*,", re.I)


_PROTECTED_SURICATA_ROOTS = tuple(
    Path(path) for path in ("/etc/suricata", "/var/lib/suricata", "/var/log/suricata")
)


def _validate_isolated_root(path: Path) -> Path:
    """Validate the supplied root before resolving any symlink components."""
    raw = Path(path)
    current = raw
    while True:
        if current.is_symlink():
            raise CandidateReplayError("Candidate isolated root or parent is symlinked")
        if current.parent == current:
            break
        current = current.parent
    if not raw.is_absolute() or not raw.is_dir():
        raise CandidateReplayError("Candidate isolated root is missing or unsafe")
    try:
        resolved = raw.resolve(strict=True)
    except OSError as exc:
        raise CandidateReplayError("Candidate isolated root cannot be resolved") from exc
    if any(
        resolved == protected or resolved.is_relative_to(protected)
        for protected in _PROTECTED_SURICATA_ROOTS
    ):
        raise CandidateReplayError("Candidate isolated root is a protected production path")
    if not resolved.name.startswith("isolated-candidate-"):
        raise CandidateReplayError("Candidate isolated root is outside the approved workspace")
    return resolved


def load_independent_case_manifest(
    path: Path, expected_sha256: str, candidate: dict,
) -> tuple[dict, list[dict]]:
    """Load the reviewed case inventory; caller-supplied inventories are rejected."""
    manifest_path = Path(path)
    if expected_sha256 != APPROVED_CASE_MANIFEST_SHA256:
        raise CandidateReplayError("Caller-supplied manifest digest is not the approved digest")
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise CandidateReplayError("Pinned independent case manifest is required")
    if sha256_file(manifest_path) != APPROVED_CASE_MANIFEST_SHA256:
        raise CandidateReplayError("Independent case manifest hash mismatch")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CandidateReplayError("Independent case manifest is invalid") from exc
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema_version") != "candidate_independent_replay_manifest_v1"
        or manifest.get("candidate_id") != candidate.get("candidate_id")
        or manifest.get("sid") != candidate.get("sid")
        or manifest.get("discovery_pcap_sha256") != candidate.get("pcap_sha256")
        or manifest.get("discovery_excluded") is not True
        or type(manifest.get("minimum_attack_cases")) is not int
        or type(manifest.get("minimum_normal_cases")) is not int
        or not isinstance(manifest.get("cases"), list)
    ):
        raise CandidateReplayError("Independent case manifest identity or exclusion gate failed")
    cases = manifest["cases"]
    if len(cases) != 5 or manifest["minimum_attack_cases"] != 2 or manifest["minimum_normal_cases"] != 3:
        raise CandidateReplayError("Frozen independent cohort must contain exactly 2 Attack and 3 Normal cases")
    counts = {"attack": 0, "normal": 0}
    ids: set[str] = set()
    expected_ids = set(APPROVED_INDEPENDENT_CASES)
    for case in cases:
        if not isinstance(case, dict) or not _ID.fullmatch(str(case.get("id", ""))):
            raise CandidateReplayError("Independent manifest contains an invalid case ID")
        if case["id"] in ids or case.get("scenario") not in counts or not _HEX.fullmatch(str(case.get("pcap_sha256"))):
            raise CandidateReplayError("Independent manifest contains a duplicate or invalid case")
        if case.get("pcap_sha256") == candidate["pcap_sha256"]:
            raise CandidateReplayError("Discovery PCAP is present in independent manifest")
        expected_scenario, expected_pcap = APPROVED_INDEPENDENT_CASES[case["id"]] if case["id"] in expected_ids else (None, None)
        if case["id"] not in expected_ids or case.get("scenario") != expected_scenario or case.get("pcap_sha256") != expected_pcap:
            raise CandidateReplayError("Independent manifest differs from the approved inventory")
        if case["pcap_sha256"] == candidate["pcap_sha256"]:
            raise CandidateReplayError("Discovery PCAP is present in independent manifest")
        ids.add(case["id"])
        counts[case["scenario"]] += 1
    if counts != {"attack": 2, "normal": 3}:
        raise CandidateReplayError("Independent manifest does not meet the minimum evaluation cohort")
    return manifest, cases


def resolve_manifest_pcap_path(
    manifest_path: str, *, pcap_root: Path, manifest_prefix: str,
) -> Path:
    """Map one reviewed repository path into an approved VM PCAP root."""
    if not isinstance(manifest_prefix, str) or not manifest_prefix:
        raise CandidateReplayError("Manifest prefix must be non-empty")
    if (
        "\\" in manifest_prefix
        or manifest_prefix.startswith("/")
        or re.match(r"^[A-Za-z]:", manifest_prefix)
        or any(part in {"", ".", ".."} for part in manifest_prefix.split("/"))
    ):
        raise CandidateReplayError("Manifest prefix must be a strict relative POSIX path")
    if not isinstance(manifest_path, str) or not manifest_path or "\\" in manifest_path:
        raise CandidateReplayError("Manifest PCAP path must be a relative POSIX path")
    raw = PurePosixPath(manifest_path)
    prefix = PurePosixPath(manifest_prefix)
    if raw.is_absolute() or prefix.is_absolute() or re.match(r"^[A-Za-z]:", manifest_path) or ".." in raw.parts:
        raise CandidateReplayError("Absolute or traversal PCAP path rejected")
    if len(raw.parts) <= len(prefix.parts) or raw.parts[:len(prefix.parts)] != prefix.parts:
        raise CandidateReplayError("Manifest PCAP path is outside the approved prefix")
    root = Path(pcap_root)
    if root.is_symlink() or not root.is_dir():
        raise CandidateReplayError("Approved PCAP root is missing or symlinked")
    suffix = raw.parts[len(prefix.parts):]
    candidate = root.joinpath(*suffix)
    try:
        resolved_root = root.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise CandidateReplayError("Manifest PCAP is missing or unresolved") from exc
    if not resolved.is_relative_to(resolved_root):
        raise CandidateReplayError("Manifest PCAP symlink escapes approved root")
    if not resolved.is_file() or candidate.is_symlink():
        raise CandidateReplayError("Manifest PCAP is missing or symlinked")
    return resolved


def _run(
    argv: list[str], *, timeout: int, cwd: Path | None = None,
) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, check=False,
            cwd=str(cwd) if cwd is not None else None,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CandidateReplayError("Suricata command failed or timed out") from exc
    if result.returncode != 0:
        raise CandidateReplayError("Suricata command returned nonzero status")
    return result


def _exclusive_run_root(root: Path) -> tuple[str, Path]:
    evidence = root / "replay-evidence"
    runs = evidence / "signing-runs"
    if any(path.is_symlink() for path in (evidence, runs)):
        raise CandidateReplayError("Replay evidence directory is symlinked")
    evidence.mkdir(mode=0o700, parents=True, exist_ok=True)
    runs.mkdir(mode=0o700, exist_ok=True)
    for _ in range(5):
        run_id = secrets.token_hex(16)
        path = runs / run_id
        try:
            path.mkdir(mode=0o700)
            return run_id, path
        except FileExistsError:
            continue
    raise CandidateReplayError("Replay signing run collision")


def _read_eve(path: Path, sid: int) -> tuple[int, int, str]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
        raise CandidateReplayError("Missing or empty fresh EVE evidence")
    events = 0
    alerts = 0
    try:
        with path.open("r", encoding="utf-8") as stream:
            for line in stream:
                if not line.strip():
                    continue
                data = json.loads(line)
                if not isinstance(data, dict):
                    raise CandidateReplayError("EVE event is not an object")
                events += 1
                if data.get("event_type") == "alert" and data.get("alert", {}).get("signature_id") == sid:
                    alerts += 1
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CandidateReplayError("EVE evidence is invalid") from exc
    if events == 0:
        raise CandidateReplayError("EVE evidence contains no events")
    return alerts, events, sha256_file(path)


def _verify_candidate_sources(
    candidate: dict, *, artifact_dir: Path, calibration_manifest: Path, baseline_rules: Path,
) -> None:
    if (
        not verify_candidate_record(candidate)
        or candidate.get("candidate_record_schema") != "candidate_record_v1"
        or candidate.get("state") not in (None, "PROPOSED")
        or candidate.get("replay_evidence", {}).get("status") not in (None, "not_available")
    ):
        raise CandidateReplayError("Candidate record is not valid candidate_record_v1")
    try:
        rebuilt = build_candidate_record(artifact_dir, calibration_manifest, baseline_rules)
    except (CandidateRecordError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CandidateReplayError("Immutable candidate source verification failed") from exc
    fields = (
        "candidate_id", "run_id", "sid", "rule", "rule_sha256",
        "source_rule_file_sha256", "source_metadata_sha256", "review_sha256",
        "pcap_sha256", "model_sha256", "calibration_sha256",
        "decision_manifest_sha256", "baseline_rules_sha256",
    )
    if any(candidate.get(field) != rebuilt.get(field) for field in fields):
        raise CandidateReplayError("Candidate record does not match immutable source artifacts")


def attest_candidate_replay(
    *, candidate: dict, artifact_dir: Path, calibration_manifest: Path,
    baseline_rules: Path, case_manifest: Path, expected_case_manifest_sha256: str,
    isolated_yaml: Path, pcap_root: Path, manifest_prefix: str,
    isolated_root: Path, private_key_pem: bytes, private_key_password: bytes,
    replay_public_pem: bytes, suricata_binary: str = "/usr/bin/suricata",
) -> dict:
    """Execute and sign a fresh candidate-specific Attack/Normal replay."""
    _verify_candidate_sources(
        candidate, artifact_dir=Path(artifact_dir),
        calibration_manifest=Path(calibration_manifest), baseline_rules=Path(baseline_rules),
    )
    try:
        require_pinned_replay_key(replay_public_pem)
    except ValueError as exc:
        raise CandidateReplayError("Replay signing key is not independently pinned") from exc
    root = _validate_isolated_root(Path(isolated_root))
    manifest, cases = load_independent_case_manifest(
        case_manifest, expected_case_manifest_sha256, candidate,
    )
    seen: set[str] = set()
    observations: list[dict] = []
    for case in cases:
        if not isinstance(case, dict) or not _ID.fullmatch(str(case.get("id", ""))):
            raise CandidateReplayError("Invalid independent replay case")
        case_id = case["id"]
        scenario = case.get("scenario")
        digest = case.get("pcap_sha256")
        if case_id in seen or scenario not in {"attack", "normal"} or not _HEX.fullmatch(str(digest)):
            raise CandidateReplayError("Duplicate or malformed independent replay case")
        if digest == candidate["pcap_sha256"]:
            raise CandidateReplayError("Discovery PCAP cannot be an independent replay case")
        resolved_pcap = resolve_manifest_pcap_path(
            case.get("pcap_path"), pcap_root=pcap_root, manifest_prefix=manifest_prefix,
        )
        if sha256_file(resolved_pcap) != digest:
            raise CandidateReplayError("Independent PCAP is missing or hash-mismatched")
        case["resolved_pcap_path"] = str(resolved_pcap)
        seen.add(case_id)
    labels = {case.get("scenario") for case in cases}
    if labels != {"attack", "normal"} or len(seen) != len(cases):
        raise CandidateReplayError("Both independent Attack and Normal cases are required")
    rule_path = Path(artifact_dir) / "ml-generated.rules"
    raw_rule = rule_path.read_bytes()
    if raw_rule != candidate["rule"].encode("utf-8") + b"\n":
        raise CandidateReplayError("Candidate rule bytes changed")
    if sha256_file(rule_path) != candidate["source_rule_file_sha256"]:
        raise CandidateReplayError("Candidate rule file hash mismatch")
    config_sha = _config_safe(Path(isolated_yaml), root)
    version = _run([suricata_binary, "-V"], timeout=30).stdout.strip()
    if "8.0.3" not in version:
        raise CandidateReplayError("Suricata 8.0.3 is required")
    replay_run_id, run_root = _exclusive_run_root(root)
    syntax_dir = run_root / "syntax"
    syntax_dir.mkdir(mode=0o700)
    _run([
        suricata_binary, "-T", "--init-errors-fatal", "-c", str(isolated_yaml),
        "-S", str(rule_path), "-l", str(syntax_dir),
    ], timeout=120, cwd=Path(isolated_yaml).parent)
    threshold_match = _THRESHOLD.search(candidate["rule"])
    if not threshold_match:
        raise CandidateReplayError("Candidate rule has no measurable detection threshold")
    threshold = int(threshold_match.group(1))
    for case in sorted(cases, key=lambda value: value["id"]):
        case_dir = run_root / case["id"]
        case_dir.mkdir(mode=0o700)
        _run([
            suricata_binary, "-r", case["resolved_pcap_path"],
            "-k", "none", "--init-errors-fatal", "-c", str(isolated_yaml),
            "-S", str(rule_path), "-l", str(case_dir),
        ], timeout=300, cwd=Path(isolated_yaml).parent)
        alerts, events, eve_sha = _read_eve(case_dir / "eve.json", candidate["sid"])
        if (case["scenario"] == "attack" and alerts < 1) or (case["scenario"] == "normal" and alerts != 0):
            raise CandidateReplayError("Candidate Attack/Normal safety gate failed")
        observations.append({
            "run_id": case["id"], "scenario": case["scenario"],
            "pcap_sha256": case["pcap_sha256"], "eve_sha256": eve_sha,
            "events": events, "candidate_sid_alerts": alerts,
        })
    record = {
        "schema_version": "isolated_replay_attestation_v1",
        "experiment_id": f"suricata-isolated-candidate-{candidate['sid']}",
        "candidate_id": candidate["candidate_id"], "run_id": candidate["run_id"],
        "replay_run_id": replay_run_id, "pcap_sha256": candidate["pcap_sha256"],
        "sid": candidate["sid"], "rule_sha256": candidate["rule_sha256"],
        "source_rule_file_sha256": candidate["source_rule_file_sha256"],
        "source_metadata_sha256": candidate["source_metadata_sha256"],
        "review_sha256": candidate["review_sha256"],
        "model_sha256": candidate["model_sha256"],
        "calibration_sha256": candidate["calibration_sha256"],
        "decision_manifest_sha256": candidate["decision_manifest_sha256"],
        "baseline_rules_sha256": candidate["baseline_rules_sha256"],
        "case_manifest_sha256": expected_case_manifest_sha256,
        "case_manifest_schema": manifest["schema_version"],
        "minimum_attack_cases": manifest["minimum_attack_cases"],
        "minimum_normal_cases": manifest["minimum_normal_cases"],
        "isolated_config_sha256": config_sha, "suricata_version": version,
        "syntax_authenticated": True, "attack_replay_passed": True,
        "normal_replay_passed": True, "normal_false_positive_count": 0,
        "threshold": threshold, "cases": observations,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    signed = sign_record(record, private_key_pem, private_key_password, domain="isolated-replay-v1")
    if not verify_signed_replay_evidence(candidate, signed, replay_public_pem):
        raise CandidateReplayError("Signer output failed independent candidate replay verification")
    return signed
