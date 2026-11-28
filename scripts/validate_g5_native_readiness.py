"""Perform non-live Suricata 8.0.3 readiness validation for a future G5 attempt."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from pathlib import Path

import yaml

from netids.isolated_suricata_runtime import (
    generate_effective_suricata_configuration,
    validate_attempt_namespace,
    validate_unix_socket_path,
)
from netids.privilege_separation import PrivilegeSeparationError, runtime_output_paths


_ATTEMPT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_PRODUCTION_ROOTS = tuple(Path(path) for path in ("/etc/suricata", "/var/lib/suricata", "/run/suricata", "/var/run/suricata"))


class NativeReadinessError(ValueError):
    """The non-live native readiness contract is not satisfied."""


def _write_exclusive(path: Path, value: dict) -> None:
    if path.exists() or path.is_symlink():
        raise NativeReadinessError("readiness report already exists; refuse overwrite")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def _redact(value: object) -> str:
    text = str(value)
    text = re.sub(r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", "[REDACTED_PRIVATE_KEY]", text, flags=re.DOTALL)
    return re.sub(r"(?i)(password|passphrase|private[_ -]?key|secret|token|credential)(\s*[:=]\s*)\S+", r"\1\2[REDACTED]", text)


def _under(path: Path, root: Path) -> bool:
    try:
        return path.resolve().is_relative_to(root.resolve())
    except OSError:
        return False


def _is_production_path(path: Path) -> bool:
    resolved = path.resolve()
    return any(
        resolved == root.resolve() or resolved.is_relative_to(root.resolve())
        for root in _PRODUCTION_ROOTS
    )


def _load_template(path: Path, root: Path) -> dict:
    if path.is_symlink() or not path.is_file() or not _under(path, root):
        raise NativeReadinessError("isolated configuration template must be a regular file under isolated root")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise NativeReadinessError("isolated configuration template is invalid") from exc
    if not isinstance(data, dict):
        raise NativeReadinessError("isolated configuration template is not an object")
    captures = data.get("af-packet")
    if not isinstance(captures, list) or not captures or any(
        not isinstance(item, dict) or item.get("interface") != "lo" for item in captures
    ):
        raise NativeReadinessError("effective isolated configuration must declare AF_PACKET on lo")
    return data


def validate_native_readiness(
    *, template_config: Path, isolated_root: Path, attempt_id: str,
    candidate_rules: Path, suricata: str = "/usr/bin/suricata", report_path: Path | None = None,
) -> dict:
    """Validate version, paths and syntax without starting a daemon or replaying traffic."""
    root = Path(isolated_root).resolve()
    if not root.is_dir() or root.is_symlink():
        raise NativeReadinessError("isolated root is missing or unsafe")
    if not isinstance(attempt_id, str) or not _ATTEMPT_ID.fullmatch(attempt_id):
        raise NativeReadinessError("invalid attempt identifier")
    try:
        attempt_root, future_socket_path = validate_attempt_namespace(root, attempt_id)
    except ValueError as exc:
        raise NativeReadinessError(str(exc)) from exc
    candidate = Path(candidate_rules).resolve()
    if _is_production_path(candidate):
        raise NativeReadinessError("production rules may not be loaded for readiness")
    if candidate.is_symlink() or not candidate.is_file():
        raise NativeReadinessError("candidate rules must be a regular file")

    configuration = _load_template(Path(template_config), root)
    readiness_root = root / "readiness" / attempt_id
    if readiness_root.exists() or readiness_root.is_symlink():
        raise NativeReadinessError("readiness namespace already exists; refuse reuse")
    readiness_root.mkdir(mode=0o700, parents=True)
    rules_root = readiness_root / "rules"
    runtime_root = readiness_root / "runtime"
    logs_root = readiness_root / "logs"
    validation_logs_root = readiness_root / "validation-logs"
    for directory in (rules_root, runtime_root, logs_root, validation_logs_root):
        directory.mkdir(mode=0o700)
    (rules_root / "active.rules").write_bytes(b"# readiness baseline: no candidate rules loaded\n")
    socket_path = runtime_root / "lab-suricata.socket"
    try:
        validate_unix_socket_path(socket_path)
        effective_text = generate_effective_suricata_configuration(
            configuration, active_rules=rules_root / "active.rules", socket_path=socket_path,
        )
        effective = yaml.safe_load(effective_text)
        runtime_output_paths(effective, logs_root)
    except ValueError as exc:
        raise NativeReadinessError(str(exc)) from exc
    except (OSError, UnicodeError, yaml.YAMLError, PrivilegeSeparationError) as exc:
        raise NativeReadinessError("native readiness output path is unsafe") from exc
    effective_config = readiness_root / "suricata.yaml"
    # Preserve the native YAML header bytes exactly on Windows and Linux.
    effective_config.write_bytes(effective_text.encode("utf-8"))

    version = subprocess.run(
        [suricata, "-V"], capture_output=True, text=True, timeout=30, check=False,
    )
    version_output = _redact(version.stdout + version.stderr)
    if version.returncode != 0 or "8.0.3" not in version_output:
        raise NativeReadinessError("Suricata 8.0.3 native version check failed")

    syntax_command = [
        suricata, "-T", "--init-errors-fatal", "-c", str(effective_config),
        "-S", str(candidate), "-l", str(validation_logs_root),
    ]
    syntax = subprocess.run(
        syntax_command, capture_output=True, text=True, timeout=120, check=False,
        cwd=readiness_root,
    )
    if syntax.returncode != 0:
        raise NativeReadinessError(
            "Suricata native syntax validation failed: "
            + _redact(syntax.stderr or syntax.stdout)
        )
    result = {
        "schema_version": "g5_native_readiness_v1",
        "status": "READY_FOR_REVIEWED_AUTHORIZATION",
        "live_operation": False,
        "activation_attempted": False,
        "traffic_replay_attempted": False,
        "nonce_consumed": False,
        "suricata_version": "8.0.3",
        "attempt_id": attempt_id,
        "future_attempt_root": str(attempt_root),
        "future_control_socket": str(future_socket_path),
        "readiness_root": str(readiness_root),
        "effective_config": str(effective_config),
        "active_rules": str(rules_root / "active.rules"),
        "validation_log_directory": str(validation_logs_root),
        "candidate_rules": str(candidate),
        "control_socket": str(socket_path),
        "syntax_command": syntax_command,
        "syntax_stdout": _redact(syntax.stdout),
        "syntax_stderr": _redact(syntax.stderr),
    }
    if report_path is not None:
        report = Path(report_path).resolve()
        if not report.is_relative_to(readiness_root):
            raise NativeReadinessError("readiness report must remain inside readiness namespace")
        _write_exclusive(report, result)
        result["report_path"] = str(report)
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--template-config", type=Path, required=True)
    parser.add_argument("--isolated-root", type=Path, required=True)
    parser.add_argument("--attempt-id", required=True)
    parser.add_argument("--candidate-rules", type=Path, required=True)
    parser.add_argument("--suricata", default="/usr/bin/suricata")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    result = validate_native_readiness(
        template_config=args.template_config, isolated_root=args.isolated_root,
        attempt_id=args.attempt_id, candidate_rules=args.candidate_rules,
        suricata=args.suricata, report_path=args.report,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
