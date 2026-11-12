"""Run real OFFLINE Suricata 8.0.3 PCAP replays before signing their results.

This runs only --pcap-file (-r) with a dedicated isolated YAML and -S
exclusive rule file. It never captures a live interface or changes a service.
A trusted replay key is held separately on the VM1 operator account.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import yaml

from netids.lifecycle_ed25519 import sha256_file, sign_record
from netids.rulegen import collect_sids

SID = 9103003
RULE_SHA = "7182bb328ce4ed1230c6de9b20c825d458b8c224a494d6b2a60063cca5ec21df"
MODEL_SHA = "206dadafc8d6cd96e21d838a52211d9b06d4a6ec541ea5c9a9ae8a6724ffbf5d"
CAL_SHA = "814e17006c5cfee433477128e9d29abf7e403e28948d78a968c46c800b67e060"
DECISION_SHA = "c7dffd3021d0c0195789e45c369f30108186753076b95586a2d80c9c744b579a"
DOCUMENTED_EVIDENCE_PATH = "artifacts/milestones-4-6-acceptance-20261112/evidence.md"
DOCUMENTED_EVIDENCE_GIT_BLOB_SHA = "4f61d7829ec566c4084444904c6e3bf5955e3f5f"
DOCUMENTED_EVIDENCE_SHA = "e9d17a8874576ab0a579b15897abe0562d412d624907f6548acae2fb0f788dac"
EXPECTED_CASES = {
    "worker-attack-holdout-01-20261111": ("attack", "7eb27fe774c8d889480662eaaea1e68b2336cc04c943ff06be399a24e4c0bbb5"),
    "worker-attack-holdout-02-20261111": ("attack", "80b118068f89f0939d9a3c9ba72c977b08f95eff74a04e65b31cd548e0258f61"),
    "worker-attack-holdout-03-20261111": ("attack", "837dd0b52f3472ce620baf9479f7f44da7515901455f54e2fe907277648a3343"),
    "worker-normal-holdout-01-20261111": ("normal", "a4500b006908c26ffeed932244148c7372f2be2cb8abeb954cfe17ad3cda0fe7"),
    "worker-normal-holdout-02-20261111": ("normal", "aad42d5710eb1006b76b744983744f47322137b2703126537b46787e34b01aaf"),
    "worker-normal-holdout-03-20261111": ("normal", "5a61ae059d8f25a2aa6bf1672f82d66c36f3e64de8d9d01dde6afca5081a2468"),
}
_BAD_PATHS = ("/var/log/suricata", "/run/suricata", "/var/run/suricata")
_HEX = re.compile(r"^[a-f0-9]{64}$")


class ReplayGateError(ValueError):
    pass


def validate_documented_rule_provenance(provenance: dict | None) -> None:
    """Require explicit recovery provenance when historical RST metadata is absent."""
    if not isinstance(provenance, dict):
        raise ReplayGateError("Documented-frozen rule provenance is required")
    if (
        provenance.get("evidence_class") != "documented_frozen_rule_recovery"
        or provenance.get("historical_generated_metadata") != "unavailable_not_recovered"
        or provenance.get("source_document_path") != DOCUMENTED_EVIDENCE_PATH
        or provenance.get("source_document_git_blob_sha256") != DOCUMENTED_EVIDENCE_GIT_BLOB_SHA
        or provenance.get("source_document_sha256") != DOCUMENTED_EVIDENCE_SHA
    ):
        raise ReplayGateError("Historical generated metadata was not recovered; explicit documented-source proof is required")


def _under(path: Path, root: Path) -> Path:
    path = Path(path)
    if path.is_symlink() or any(part.is_symlink() for part in path.parents):
        raise ReplayGateError("Symlink not allowed in isolated output path")
    absolute = path.resolve()
    if not absolute.is_relative_to(root) or absolute == root:
        raise ReplayGateError("Output path escapes isolated root")
    return absolute


def _config_safe(config_path: Path, root: Path) -> str:
    path = _under(config_path, root)
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError, UnicodeError) as exc:
        raise ReplayGateError("Invalid isolated YAML configuration") from exc
    if not isinstance(data, dict):
        raise ReplayGateError("Isolated YAML is not an object")
    for capture_section in ("af-packet", "pcap"):
        for entry in data.get(capture_section, []):
            if isinstance(entry, dict) and entry.get("interface") not in ("lo", None):
                raise ReplayGateError("Isolated YAML references a non-loopback capture interface")
    outputs = data.get("outputs")
    if not isinstance(outputs, list):
        raise ReplayGateError("Isolated YAML must configure outputs")
    eve_enabled = False
    for item in outputs:
        if not isinstance(item, dict):
            raise ReplayGateError("Invalid YAML output")
        for name, opts in item.items():
            if not isinstance(opts, dict):
                continue
            for field in ("filename", "file"):
                filename = opts.get(field)
                if filename is not None and (
                    not isinstance(filename, str)
                    or Path(filename).is_absolute()
                    or ".." in Path(filename).parts
                    or any(bad in filename for bad in _BAD_PATHS)
                ):
                    raise ReplayGateError("Unsafe absolute or traversal output path")
            if name in ("syslog", "alert-syslog") and opts.get("enabled", True) is not False:
                raise ReplayGateError("Isolated YAML may not emit syslog")
            if name == "eve-log" and opts.get("enabled", True) is not False:
                eve_enabled = opts.get("filename") == "eve.json"
    if not eve_enabled:
        raise ReplayGateError("Require enabled eve-log with relative eve.json filename")
    return sha256_file(path)


def _create_exclusive_run_root(root: Path, replay_run_id: str) -> Path:
    """Claim one new signing directory without touching prior evidence."""
    evidence_root = _under(root / "replay-evidence", root)
    if evidence_root.exists() and evidence_root.is_symlink():
        raise ReplayGateError("Replay evidence root may not be a symlink")
    if not evidence_root.exists():
        evidence_root.mkdir(mode=0o700, parents=False)
    run_root = _under(evidence_root / f"signed-{replay_run_id}", root)
    try:
        run_root.mkdir(mode=0o700, parents=False, exist_ok=False)
    except FileExistsError as exc:
        raise ReplayGateError("Signing replay run already exists; never overwrite or reuse it") from exc
    return run_root


def _run(command: list[str], *, timeout: int = 180) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReplayGateError("Suricata command unavailable or timed out") from exc
    if result.returncode != 0:
        raise ReplayGateError("Isolated Suricata command failed (see local operator logs)")
    return result


def _candidate_alerts(eve_path: Path) -> tuple[int, int]:
    if eve_path.is_symlink() or not eve_path.is_file():
        raise ReplayGateError("Suricata did not create a fresh EVE JSON file")
    count = 0
    total = 0
    with eve_path.open(encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except (ValueError, UnicodeError) as exc:
                raise ReplayGateError("Malformed EVE event") from exc
            total += 1
            if event.get("event_type") == "alert":
                sid = event.get("alert", {}).get("signature_id")
                if sid != SID:
                    raise ReplayGateError("Unexpected SID in exclusive rule replay")
                count += 1
    if total == 0:
        raise ReplayGateError("Empty EVE output; cannot prove replay")
    return count, total



def verify_pinned_rule_artifact(rule_file: Path, *, expected_sid: int, expected_text_sha256: str) -> str:
    """Return original file-byte SHA only for an exact one-line reviewed rule.

    The existing backend.rule_handoff contract hashes rule text without its
    one terminal LF. Preserve raw artifact hash separately for evidence.
    """
    rule_path = Path(rule_file)
    if rule_path.is_symlink() or not rule_path.is_file():
        raise ReplayGateError("Original SID rule artifact unavailable or unsafe")
    raw_rule = rule_path.read_bytes()
    if b"\r" in raw_rule:
        raise ReplayGateError("Original generated rule must end with exactly one LF")
    if raw_rule.count(b"\n") == 1 and raw_rule.endswith(b"\n"):
        if hashlib.sha256(raw_rule[:-1]).hexdigest() != expected_text_sha256:
            raise ReplayGateError("Canonical rule-text SHA256 mismatch")
    if raw_rule.count(b"\n") != 1 or not raw_rule.endswith(b"\n"):
        raise ReplayGateError("Original generated rule must end with exactly one LF")
    rule_bytes = raw_rule[:-1]
    if hashlib.sha256(rule_bytes).hexdigest() != expected_text_sha256:
        raise ReplayGateError("Canonical rule-text SHA256 mismatch")
    try:
        rule_text = rule_bytes.decode("utf-8")
    except UnicodeError as exc:
        raise ReplayGateError("Invalid UTF-8 rule artifact") from exc
    if collect_sids([rule_text]) != {expected_sid} or not rule_text.startswith("alert tcp "):
        raise ReplayGateError("Rule is not the approved alert-only TCP signature")
    return hashlib.sha256(raw_rule).hexdigest()

def attest_six_holdouts(
    *,
    manifest_path: Path,
    expected_manifest_sha256: str,
    rule_file: Path,
    isolated_yaml: Path,
    isolated_root: Path,
    private_key_pem: bytes,
    private_key_password: bytes,
    rule_provenance: dict | None = None,
    suricata_binary: str = "/usr/bin/suricata",
) -> dict:
    """Sign only six immutable real-PCAP replays that passed all gates."""
    root = Path(isolated_root).resolve()
    if root.name != "isolated-lifecycle-9103003" or root.is_symlink():
        raise ReplayGateError("Wrong isolated root")
    if not root.exists() or not root.is_dir():
        raise ReplayGateError("Isolated root missing")
    if not _HEX.fullmatch(expected_manifest_sha256):
        raise ReplayGateError("Owner-pinned manifest hash required")
    if sha256_file(manifest_path) != expected_manifest_sha256:
        raise ReplayGateError("Replay manifest hash mismatch")
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or manifest.get("schema_version") != "suricata_replay_manifest_v1":
        raise ReplayGateError("Invalid replay manifest")
    if (
        manifest.get("sid") != SID
        or manifest.get("rule_sha256") != RULE_SHA
        or manifest.get("model_sha256") != MODEL_SHA
        or manifest.get("calibration_sha256") != CAL_SHA
        or manifest.get("decision_manifest_sha256") != DECISION_SHA
    ):
        raise ReplayGateError("Frozen provenance mismatch")
    candidate_id = manifest.get("candidate_id")
    candidate_run_id = manifest.get("run_id")
    replay_run_id = manifest.get("replay_run_id")
    candidate_pcap = manifest.get("pcap_sha256")
    if (
        not isinstance(candidate_run_id, str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", candidate_run_id)
        or not isinstance(candidate_id, str)
        or not _HEX.fullmatch(candidate_id)
        or candidate_id != hashlib.sha256(
            f"{candidate_run_id}:{SID}:{RULE_SHA}".encode()
        ).hexdigest()
        or candidate_pcap not in {
            digest for scenario, digest in EXPECTED_CASES.values()
            if scenario == "attack"
        }
        or not isinstance(replay_run_id, str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", replay_run_id)
        or replay_run_id == "documented-frozen-rule-signing-20261112-unsigned"
    ):
        raise ReplayGateError("Candidate identity or source PCAP is not pinned to an original attack holdout")
    case_list = manifest.get("cases")
    if not isinstance(case_list, list) or len(case_list) != 6:
        raise ReplayGateError("Exactly six original holdouts required")
    by_id = {}
    for case in case_list:
        if not isinstance(case, dict) or not isinstance(case.get("id"), str):
            raise ReplayGateError("Invalid replay case")
        identifier = case["id"]
        if identifier in by_id or identifier not in EXPECTED_CASES:
            raise ReplayGateError("Duplicate or unknown holdout")
        label, digest = EXPECTED_CASES[identifier]
        if case.get("scenario") != label or case.get("pcap_sha256") != digest:
            raise ReplayGateError("Holdout label or pinned hash mismatch")
        pcap_path = Path(case.get("pcap_path", ""))
        if pcap_path.is_symlink() or not pcap_path.is_file():
            raise ReplayGateError("Original holdout file missing or symlinked")
        if sha256_file(pcap_path) != digest:
            raise ReplayGateError("Original holdout bytes mismatch")
        by_id[identifier] = pcap_path.resolve(strict=True)
    if set(by_id) != set(EXPECTED_CASES):
        raise ReplayGateError("Missing original holdout")
    original_rule_file_sha256 = verify_pinned_rule_artifact(
        rule_file, expected_sid=SID, expected_text_sha256=RULE_SHA,
    )
    validate_documented_rule_provenance(rule_provenance)
    config_sha = _config_safe(isolated_yaml, root)
    version = _run([suricata_binary, "-V"], timeout=30).stdout.strip()
    if "8.0.3" not in version:
        raise ReplayGateError("Suricata 8.0.3 required")
    run_root = _create_exclusive_run_root(root, replay_run_id)
    syntax_dir = run_root / "syntax"
    syntax_dir.mkdir(mode=0o700)
    _run([
        suricata_binary, "-T", "--init-errors-fatal",
        "-c", str(isolated_yaml), "-S", str(rule_file), "-l", str(syntax_dir),
    ], timeout=120)
    observations = []
    for identifier in sorted(by_id):
        case_dir = run_root / identifier
        case_dir.mkdir(mode=0o700)
        _run([
            suricata_binary, "-r", str(by_id[identifier]), "-k", "none",
            "--init-errors-fatal", "-c", str(isolated_yaml),
            "-S", str(rule_file), "-l", str(case_dir),
        ], timeout=300)
        count, events = _candidate_alerts(case_dir / "eve.json")
        label, digest = EXPECTED_CASES[identifier]
        if (label == "attack" and count == 0) or (label == "normal" and count != 0):
            raise ReplayGateError("Replay false-negative or false-positive gate failed")
        observations.append({
            "run_id": identifier,
            "scenario": label,
            "pcap_sha256": digest,
            "eve_sha256": sha256_file(case_dir / "eve.json"),
            "events": events,
            "candidate_sid_alerts": count,
        })
    result = {
        "schema_version": "isolated_replay_attestation_v1",
        "experiment_id": "suricata-isolated-9103003-20261112",
        "candidate_id": manifest.get("candidate_id"),
        "run_id": manifest.get("run_id"),
        "replay_run_id": replay_run_id,
        "replay_evidence_relpath": str(run_root.relative_to(root)).replace("\\", "/"),
        "pcap_sha256": manifest.get("pcap_sha256"),
        "sid": SID,
        "rule_sha256": RULE_SHA,
        "original_rule_file_sha256": original_rule_file_sha256,
        "rule_provenance": rule_provenance,
        "model_sha256": MODEL_SHA,
        "calibration_sha256": CAL_SHA,
        "decision_manifest_sha256": DECISION_SHA,
        "manifest_sha256": expected_manifest_sha256,
        "isolated_config_sha256": config_sha,
        "suricata_version": version,
        "syntax_authenticated": True,
        "attack_replay_passed": True,
        "normal_replay_passed": True,
        "normal_false_positive_count": 0,
        "threshold": 3,
        "cases": observations,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    index = {
        "replay_run_id": replay_run_id,
        "syntax_eve_sha256": sha256_file(syntax_dir / "eve.json")
        if (syntax_dir / "eve.json").is_file() else None,
        "cases": [
            {"run_id": item["run_id"], "eve_sha256": item["eve_sha256"]}
            for item in observations
        ],
    }
    result["replay_evidence_index_sha256"] = hashlib.sha256(
        json.dumps(index, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    # Only sign after all independent Suricata subprocesses and parsed EVE gates pass.
    return sign_record(result, private_key_pem, private_key_password, domain="isolated-replay-v1")
