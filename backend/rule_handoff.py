"""Fail-closed VM3-to-VM1 review-rule handoff.

This sends only a provenance-verified review artifact to VM1's isolated lab
inbox. It never edits production Suricata configuration or reloads a service.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import subprocess
from pathlib import Path


class HandoffError(ValueError):
    """A rule handoff invariant was not met."""


RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SID = re.compile(r"\bsid:(\d+);")
TARGET = "suricata-vm1"
KNOWN_HOSTS = Path.home() / ".ssh" / "known_hosts"
REMOTE_ROOT = "/home/tanhv/suricata-rule-review/incoming"


def _hash_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _read_artifacts(artifact_dir: Path, run_id: str) -> tuple[Path, Path, str, dict]:
    if not RUN_ID.fullmatch(run_id):
        raise HandoffError("Unsafe run ID")
    root = artifact_dir.resolve(strict=True)
    rule_path = root / "ml-generated.rules"
    metadata_path = root / "ml-generated.metadata.json"
    if not rule_path.is_file() or rule_path.is_symlink() or not metadata_path.is_file() or metadata_path.is_symlink():
        raise HandoffError("Generated rule artifacts are missing or unsafe")
    rule = rule_path.read_text(encoding="utf-8")
    if not rule.endswith("\n"):
        raise HandoffError("Rule artifact must end with one newline")
    rule_text = rule[:-1]
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    if not isinstance(metadata, dict):
        raise HandoffError("Rule metadata must be an object")
    if (
        metadata.get("schema_version") != "ml_rule_metadata_v1"
        or metadata.get("run_id") != run_id
        or metadata.get("status") != "needs_review"
        or metadata.get("approved") is not False
        or metadata.get("deployable") is not False
        or metadata.get("deployed") is not False
        or not SHA256.fullmatch(metadata.get("pcap_sha256", ""))
        or not SHA256.fullmatch(metadata.get("model_sha256", ""))
        or metadata.get("rule_sha256") != _hash_bytes(rule_text.encode("utf-8"))
    ):
        raise HandoffError("Rule metadata provenance or review gate mismatch")
    sids = [int(value) for value in SID.findall(rule_text)]
    if len(sids) != 1 or sids[0] in {9102001, 9102002}:
        raise HandoffError("Rule must contain one fresh, non-rejected SID")
    return rule_path, metadata_path, rule_text, metadata


def _ssh_options() -> list[str]:
    return [
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={KNOWN_HOSTS}",
        "-o", "ConnectTimeout=10",
    ]


def send(*, artifact_dir: Path, run_id: str, execute: bool, approve: bool) -> dict:
    rule_path, metadata_path, rule_text, metadata = _read_artifacts(
        Path(artifact_dir), run_id
    )
    rule_file_sha = _hash_bytes(rule_path.read_bytes())
    if execute and not approve:
        raise HandoffError("Explicit human approval is required for execution")
    if not execute:
        return {
            "status": "validated_dry_run",
            "run_id": run_id,
            "target": TARGET,
            "remote_root": REMOTE_ROOT,
            "rule_sha256": metadata["rule_sha256"],
        }

    target = f"tanhv@{TARGET}"
    remote_dir = f"{REMOTE_ROOT}/{run_id}"
    partial_dir = remote_dir + ".partial"
    remote_rule = f"{remote_dir}/ml-generated.rules"
    remote_metadata = f"{remote_dir}/ml-generated.metadata.json"
    partial_rule = f"{partial_dir}/ml-generated.rules"
    partial_metadata = f"{partial_dir}/ml-generated.metadata.json"
    preflight = "; ".join([
        "set -eu",
        f"test -d {shlex.quote(REMOTE_ROOT)}",
        f"test -w {shlex.quote(REMOTE_ROOT)}",
        f"test ! -e {shlex.quote(remote_dir)}",
        f"test ! -e {shlex.quote(partial_dir)}",
        f"install -d -m 700 {shlex.quote(partial_dir)}",
    ])
    subprocess.run(["ssh", *_ssh_options(), target, preflight], check=True, timeout=45)
    subprocess.run(
        ["scp", "-B", *_ssh_options(), str(rule_path), f"{target}:{partial_rule}"],
        check=True,
        timeout=120,
    )
    subprocess.run(
        ["scp", "-B", *_ssh_options(), str(metadata_path), f"{target}:{partial_metadata}"],
        check=True,
        timeout=120,
    )
    promote = "; ".join([
        "set -eu",
        f"test \"$(sha256sum {shlex.quote(partial_rule)} | cut -d ' ' -f 1)\" = {rule_file_sha}",
        f"test \"$(sha256sum {shlex.quote(partial_metadata)} | cut -d ' ' -f 1)\" = {hashlib.sha256(metadata_path.read_bytes()).hexdigest()}",
        f"mv --no-target-directory {shlex.quote(partial_dir)} {shlex.quote(remote_dir)}",
    ])
    subprocess.run(["ssh", *_ssh_options(), target, promote], check=True, timeout=45)
    return {
        "status": "sent",
        "run_id": run_id,
        "target": TARGET,
        "remote_dir": remote_dir,
        "rule_sha256": metadata["rule_sha256"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--approve", action="store_true")
    args = parser.parse_args(argv)
    try:
        print(json.dumps(send(
            artifact_dir=args.artifact_dir,
            run_id=args.run_id,
            execute=args.execute,
            approve=args.approve,
        ), sort_keys=True))
    except (HandoffError, OSError, subprocess.SubprocessError) as exc:
        print(f"ERROR: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
