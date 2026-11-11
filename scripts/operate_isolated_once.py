"""Owner-gated, one-shot VM1 isolated Suricata activation and verified rollback.

This must be invoked LOCALLY on VM1 after the owner separately signs an
authorization on Windows. It never uses SSH, systemctl writes, sudo, iptables,
network interfaces other than lo, or a production rules/config path.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import re
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import yaml

from netids.lifecycle_ed25519 import sign_record, verify_record, sha256_file
from netids.isolated_suricata_runtime import (
    ROOT, VM1_HOST, IsolatedSuricataRuntime,
)
from netids.rule_lifecycle import RuleLifecycle, LifecycleError
from netids.trusted_replay import SID, RULE_SHA, MODEL_SHA, CAL_SHA, EXPECTED_CASES

_HEX = re.compile(r"^[a-f0-9]{64}$")


class OperationError(RuntimeError):
    pass


def _read_json(path: Path) -> dict:
    if Path(path).is_symlink():
        raise OperationError("Symlinked evidence is not accepted")
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise OperationError("Evidence must be an object")
    return data


def _systemd(service: str) -> tuple[str, str]:
    result = subprocess.run(
        ["systemctl", "show", "-p", "ActiveState", "-p", "MainPID", service],
        check=False, capture_output=True, text=True, timeout=20,
    )
    if result.returncode:
        raise OperationError(f"Cannot inspect {service} service")
    lines = dict(
        line.split("=", 1) for line in result.stdout.splitlines() if "=" in line
    )
    if lines.get("ActiveState") != "active" or not lines.get("MainPID", "0").isdigit():
        raise OperationError(f"{service} is not active")
    return lines["ActiveState"], lines["MainPID"]


def production_snapshot(production_yaml: Path, production_rules: Path) -> dict:
    """Read-only production proof; never reopen or modify service files."""
    if socket.gethostname() != VM1_HOST:
        raise OperationError("Target is not VM1")
    for file in (production_yaml, production_rules):
        if file.is_symlink() or not file.is_file():
            raise OperationError("Production snapshot source is missing or a symlink")
    with production_yaml.open(encoding="utf-8") as source:
        config = yaml.safe_load(source)
    if not isinstance(config, dict):
        raise OperationError("Invalid production YAML")
    for section in ("af-packet", "pcap"):
        for entry in config.get(section, []):
            if isinstance(entry, dict) and entry.get("interface") == "lo":
                raise OperationError("Production Suricata captures lo; activation forbidden")
    suricata_state, suricata_pid = _systemd("suricata")
    filebeat_state, filebeat_pid = _systemd("filebeat")
    capabilities = subprocess.run(
        ["getcap", "-v", "/usr/bin/tcpdump"],
        check=False, capture_output=True, text=True, timeout=15,
    )
    if capabilities.returncode or "cap_" in capabilities.stdout.lower():
        raise OperationError("tcpdump capability not verified as revoked")
    return {
        "suricata_active": suricata_state,
        "suricata_main_pid": suricata_pid,
        "filebeat_active": filebeat_state,
        "filebeat_main_pid": filebeat_pid,
        "production_yaml_sha256": sha256_file(production_yaml),
        "production_rules_sha256": sha256_file(production_rules),
        "tcpdump_capabilities_revoked": True,
    }


def _digest(record: dict) -> str:
    return hashlib.sha256(json.dumps(
        record, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode()).hexdigest()


def _verify_inputs(
    candidate: dict, replay: dict, authorization: dict,
    replay_public: bytes, owner_public: bytes,
) -> None:
    if not verify_record(replay, replay_public, domain="isolated-replay-v1"):
        raise OperationError("Untrusted replay attestation")
    if not verify_record(authorization, owner_public, domain="isolated-owner-approval-v1"):
        raise OperationError("Untrusted owner authorization")
    if authorization.get("replay_evidence_sha256") != _digest(replay):
        raise OperationError("Owner approval does not bind the signed replay bytes")
    if (
        replay.get("candidate_id") != candidate.get("candidate_id")
        or authorization.get("candidate_id") != candidate.get("candidate_id")
        or replay.get("rule_sha256") != RULE_SHA
        or authorization.get("rule_sha256") != RULE_SHA
        or replay.get("model_sha256") != MODEL_SHA
        or replay.get("calibration_sha256") != CAL_SHA
        or authorization.get("runtime_id") != "suricata-vm1:isolated-lifecycle-9103003:lo"
        or authorization.get("target_vm") != VM1_HOST
        or authorization.get("interface") != "lo"
        or authorization.get("operation") != "activate"
        or authorization.get("rollback_required") is not True
        or authorization.get("max_activation_seconds") != 300
        or authorization.get("isolated_root") != str(ROOT)
        or candidate.get("sid") != SID
        or candidate.get("rule_sha256") != RULE_SHA
        or candidate.get("model_sha256") != MODEL_SHA
        or candidate.get("calibration_sha256") != CAL_SHA
        or authorization.get("run_id") != candidate.get("run_id")
    ):
        raise OperationError("Candidate, replay or exact owner scope mismatch")


def execute_one_time(
    *,
    candidate_file: Path, replay_attestation_file: Path,
    owner_approval_file: Path, replay_public_file: Path, owner_public_file: Path,
    production_yaml: Path, production_rules: Path,
    isolated_yaml: Path, attack_pcap: Path, normal_pcap: Path,
    audit_path: Path, replay_private_pem: bytes,
    replay_private_password: bytes,
) -> dict:
    if socket.gethostname() != VM1_HOST:
        raise OperationError("Owner authorization is only for VM1")
    if Path(audit_path).resolve() != ROOT / "audit" / "owner-once.jsonl":
        raise OperationError("Activation audit must use the fixed one-time VM1 ledger")
    candidate = _read_json(candidate_file)
    replay = _read_json(replay_attestation_file)
    approval = _read_json(owner_approval_file)
    replay_public = Path(replay_public_file).read_bytes()
    owner_public = Path(owner_public_file).read_bytes()
    _verify_inputs(candidate, replay, approval, replay_public, owner_public)
    before = production_snapshot(production_yaml, production_rules)
    if any(candidate.get(flag) is not False for flag in ("approved", "deployable", "deployed")):
        raise OperationError("Original rule candidate must remain review-only")
    if candidate.get("pcap_sha256") != replay.get("pcap_sha256"):
        raise OperationError("Candidate PCAP SHA mismatch")
    if not (
        _HEX.fullmatch(str(candidate.get("candidate_id")))
        and _HEX.fullmatch(str(candidate.get("rule_sha256")))
    ):
        raise OperationError("Malformed candidate identity/hash")
    lifecycle = RuleLifecycle(
        audit_path,
        isolated_root=ROOT,
        replay_verification_key=replay_public,
        owner_verification_key=owner_public,
        attestation_mode="ed25519",
    )
    proposed = lifecycle.create_candidate(candidate)
    if proposed["candidate_id"] != candidate["candidate_id"]:
        raise OperationError("Candidate ID mismatch")
    lifecycle.transition(proposed, "VALIDATING")
    lifecycle.record_validation(proposed, replay)
    lifecycle.transition(proposed, "AWAITING_APPROVAL")
    lifecycle.approve(proposed, approval)
    attack_digest = EXPECTED_CASES["worker-attack-holdout-01-20261111"][1]
    normal_digest = EXPECTED_CASES["worker-normal-holdout-01-20261111"][1]
    runtime = IsolatedSuricataRuntime(
        config=isolated_yaml,
        attack_pcap=attack_pcap,
        attack_sha256=attack_digest,
        normal_pcap=normal_pcap,
        normal_sha256=normal_digest,
    )
    started = datetime.now(timezone.utc)
    outcome = "FAILED"
    try:
        staged = lifecycle.stage(proposed, ROOT / "rules", activate=True, runtime=runtime)
        if staged.get("status") != "active_in_isolated_lab":
            raise OperationError("Isolated runtime did not verify active state")
        # Always attempt rollback after ACTIVE, even if the time budget is exhausted.
        lifecycle.rollback(proposed, runtime=runtime)
        if proposed["state"] != "ROLLED_BACK":
            raise OperationError("Real runtime rollback not verified")
        if (datetime.now(timezone.utc) - started).total_seconds() > 300:
            raise OperationError("Owner-authorized operation exceeded 300 seconds")
        outcome = "VERIFIED_ISOLATED_ACTIVATION_AND_ROLLBACK"
    finally:
        runtime.shutdown()
    after = production_snapshot(production_yaml, production_rules)
    if before != after:
        raise OperationError("Production before/after evidence differs; fail acceptance")
    record = {
        "schema_version": "isolated_runtime_acceptance_v1",
        "candidate_id": proposed["candidate_id"],
        "run_id": proposed["run_id"],
        "sid": SID,
        "rule_sha256": RULE_SHA,
        "replay_evidence_sha256": _digest(replay),
        "owner_approval_sha256": _digest(approval),
        "suricata_version": "8.0.3",
        "runtime_id": approval["runtime_id"],
        "interface": "lo",
        "outcome": outcome,
        "started_at": started.isoformat(),
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "production_before": before,
        "production_after": after,
        "lifecycle_audit_records": lifecycle.verify_audit(),
        "approved": False,
        "deployable": False,
        "deployed": False,
    }
    return sign_record(
        record, replay_private_pem, replay_private_password, domain="isolated-runtime-v1"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "candidate-file", "replay-attestation-file", "owner-approval-file",
        "replay-public-file", "owner-public-file", "production-yaml",
        "production-rules", "isolated-yaml", "attack-pcap", "normal-pcap",
        "audit-path", "replay-private-file", "evidence-output",
    ):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args(argv)
    if args.evidence_output.exists():
        parser.error("Evidence already exists, no overwrite permitted")
    print("This command attempts ONE owner-signed isolated activation and rollback.")
    print("Target: suricata-vm1, lo only, Suricata 8.0.3, SID 9103003.")
    print("Never run against production config or production rules.")
    password = getpass.getpass("VM1 replay/runtime signing key passphrase: ").encode()
    evidence = execute_one_time(
        candidate_file=args.candidate_file,
        replay_attestation_file=args.replay_attestation_file,
        owner_approval_file=args.owner_approval_file,
        replay_public_file=args.replay_public_file,
        owner_public_file=args.owner_public_file,
        production_yaml=args.production_yaml,
        production_rules=args.production_rules,
        isolated_yaml=args.isolated_yaml,
        attack_pcap=args.attack_pcap,
        normal_pcap=args.normal_pcap,
        audit_path=args.audit_path,
        replay_private_pem=args.replay_private_file.read_bytes(),
        replay_private_password=password,
    )
    args.evidence_output.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(args.evidence_output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(evidence, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    print("Verified signed isolated runtime evidence:", args.evidence_output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
