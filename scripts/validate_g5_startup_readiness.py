"""Guarded startup-only G5 readiness smoke test for later owner review.

This procedure is deliberately separate from the frozen candidate operation. It
creates a fresh readiness namespace, validates an empty ruleset, proves the
dedicated account can open only the declared runtime outputs, starts Suricata
long enough to verify privilege drop and socket readiness, then shuts it down.
It has no candidate, replay, lifecycle, authorization, nonce, or systemd path.
The CLI refuses to run unless both an explicit flag and an owner-review
environment guard are present. This module is not executed by CI.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import yaml

from netids.isolated_suricata_runtime import (
    _BoundedProcessOutput, _redact_diagnostic, generate_effective_suricata_configuration,
    validate_attempt_id,
)
from netids.privilege_separation import (
    AttemptAccessPaths, PrivilegeSeparationError, SERVICE_GID, SERVICE_GROUP,
    SERVICE_UID, SERVICE_USER, apply_attempt_acls, confine_configuration_references,
    lookup_service_account, prepare_runtime_output_files, read_process_identity,
    referenced_configuration_files, remove_attempt_acls,
    require_root_operator_if_supported, verify_attempt_socket_path,
)
from netids.trusted_replay import ReplayGateError, _config_safe


class StartupReadinessError(RuntimeError):
    """The guarded startup-only readiness contract was not satisfied."""


def require_startup_smoke_guard(argv, environment) -> None:
    if "--execute-startup-smoke" not in argv or environment.get("G5_STARTUP_READINESS") != "OWNER_REVIEWED":
        raise StartupReadinessError(
            "explicit startup smoke guard and G5_STARTUP_READINESS=OWNER_REVIEWED are required"
        )


def build_startup_command(
    *, suricata: str, config: Path, logs: Path, pidfile: Path,
    service_user: str = SERVICE_USER, service_group: str = SERVICE_GROUP,
) -> list[str]:
    return [
        suricata, "-c", str(config), "-l", str(logs), "--af-packet=lo",
        "--pidfile", str(pidfile), "--init-errors-fatal", "-k", "none",
        f"--user={service_user}", f"--group={service_group}",
    ]


def build_output_access_command(
    *, setpriv: str, python: str, output_files: tuple[Path, ...],
) -> list[str]:
    code = "import sys; [open(path, 'a').close() for path in sys.argv[1:]]"
    return [
        setpriv, f"--reuid={SERVICE_UID}", f"--regid={SERVICE_GID}",
        "--clear-groups", "--", python, "-c", code,
        *(str(path) for path in output_files),
    ]


def _write_exclusive(path: Path, value: dict) -> None:
    if path.exists() or path.is_symlink():
        raise StartupReadinessError("readiness report already exists; refuse overwrite")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def _terminate_and_verify(process) -> bool:
    if process.poll() is not None:
        return True
    try:
        process.terminate()
        process.wait(timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        try:
            process.kill()
            process.wait(timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            return False
    return process.poll() is not None


def _socket_command(
    runner, *, suricatasc: str, command: str, socket_path: Path, cwd: Path,
) -> object:
    result = runner(
        [suricatasc, "-c", command, str(socket_path)],
        capture_output=True, text=True, timeout=30, check=False,
        shell=False, cwd=cwd,
    )
    if result.returncode != 0:
        raise StartupReadinessError(
            "suricatasc failed: " + _redact_diagnostic(getattr(result, "stderr", ""))
        )
    try:
        response = json.loads(result.stdout)
    except (TypeError, ValueError) as exc:
        raise StartupReadinessError("suricatasc returned invalid JSON") from exc
    if not isinstance(response, dict) or response.get("return") != "OK":
        raise StartupReadinessError("suricatasc returned a non-OK response")
    return response.get("message")


def run_startup_readiness(
    *, template_config: Path, isolated_root: Path, attempt_id: str,
    suricata: str = "/usr/bin/suricata", suricatasc: str = "/usr/bin/suricatasc",
    setpriv: str = "/usr/bin/setpriv", report_path: Path | None = None,
    startup_timeout: float = 30.0, runner=subprocess.run, popen=subprocess.Popen,
    guarded: bool = False,
) -> dict:
    """Run only the guarded empty-ruleset startup/shutdown smoke procedure."""
    if not guarded:
        raise StartupReadinessError("startup readiness requires the explicit owner-review guard")
    require_root_operator_if_supported()
    lookup_service_account(SERVICE_USER, SERVICE_GROUP)
    try:
        validate_attempt_id(attempt_id)
    except ValueError as exc:
        raise StartupReadinessError(str(exc)) from exc
    root = Path(isolated_root).resolve()
    source = Path(template_config)
    if not root.is_dir() or root.is_symlink() or source.is_symlink() or not source.is_file():
        raise StartupReadinessError("isolated root or template is missing/unsafe")
    if not source.resolve().is_relative_to(root):
        raise StartupReadinessError("template must remain inside isolated root")
    try:
        _config_safe(source, root)
    except (OSError, UnicodeError, ReplayGateError) as exc:
        raise StartupReadinessError("isolated configuration is unsafe") from exc

    readiness_parent = root / "readiness"
    if readiness_parent.is_symlink() or (readiness_parent.exists() and not readiness_parent.is_dir()):
        raise StartupReadinessError("readiness parent is missing or symlinked")
    readiness_root = readiness_parent / attempt_id
    if readiness_root.exists() or readiness_root.is_symlink():
        raise StartupReadinessError("readiness namespace already exists; refuse reuse")
    readiness_root.mkdir(mode=0o700, parents=True)
    rules_dir = readiness_root / "rules"
    runtime_dir = readiness_root / "runtime"
    logs_dir = readiness_root / "logs"
    validation_logs = readiness_root / "validation-logs"
    for directory in (rules_dir, runtime_dir, logs_dir, validation_logs):
        directory.mkdir(mode=0o700)
    active_rules = rules_dir / "active.rules"
    active_rules.write_bytes(b"# startup readiness empty ruleset\n")
    socket_path = runtime_dir / "lab-suricata.socket"
    pidfile = runtime_dir / "lab-suricata.pid"
    effective_config = readiness_root / "suricata.yaml"

    process = None
    transaction = None
    output_collectors = []
    cleanup_verified = False
    identity_verified = False
    socket_verified = False
    startup_error = None
    try:
        configuration = yaml.safe_load(source.read_text(encoding="utf-8"))
        confined = confine_configuration_references(
            configuration, source, attempt_root=readiness_root, allowed_root=root,
        )
        effective_text = generate_effective_suricata_configuration(
            confined, active_rules=active_rules, socket_path=socket_path,
        )
        effective_config.write_bytes(effective_text.encode("utf-8"))
        effective = yaml.safe_load(effective_text)
        references = referenced_configuration_files(
            effective, effective_config, allowed_root=readiness_root,
        )
        output_files = prepare_runtime_output_files(effective, logs_dir)
        access_paths = AttemptAccessPaths(
            attempt_root=readiness_root, runtime_dir=runtime_dir,
            rules_dir=rules_dir, active_rules=active_rules, logs_dir=logs_dir,
            effective_config=effective_config, referenced_files=references,
            runtime_output_files=output_files,
        )
        transaction = apply_attempt_acls(access_paths, runner=runner)

        version = runner(
            [suricata, "-V"], capture_output=True, text=True, timeout=30,
            check=False, shell=False, cwd=readiness_root,
        )
        if version.returncode != 0 or "8.0.3" not in (
            version.stdout + version.stderr
        ):
            raise StartupReadinessError("Suricata 8.0.3 native version check failed")
        syntax = runner(
            [suricata, "-T", "--init-errors-fatal", "-c", str(effective_config),
             "-l", str(validation_logs)],
            capture_output=True, text=True, timeout=120, check=False,
            shell=False, cwd=readiness_root,
        )
        if syntax.returncode != 0:
            raise StartupReadinessError(
                "native syntax validation failed: "
                + _redact_diagnostic(syntax.stderr or syntax.stdout)
            )
        access = runner(
            build_output_access_command(
                setpriv=setpriv, python=sys.executable, output_files=output_files,
            ), capture_output=True, text=True, timeout=30, check=False,
            shell=False, cwd=readiness_root,
        )
        if access.returncode != 0:
            raise StartupReadinessError(
                "service-account runtime output access failed: "
                + _redact_diagnostic(access.stderr or access.stdout)
            )

        process = popen(
            build_startup_command(
                suricata=suricata, config=effective_config, logs=logs_dir,
                pidfile=pidfile,
            ), cwd=readiness_root, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
        )
        output_collectors = [
            _BoundedProcessOutput(process.stdout), _BoundedProcessOutput(process.stderr),
        ]
        deadline = time.monotonic() + startup_timeout
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise StartupReadinessError(
                    f"daemon exited before privilege drop ({process.poll()})"
                )
            try:
                identity = read_process_identity(process.pid)
            except PrivilegeSeparationError:
                identity = None
            if identity is not None:
                if identity.is_expected(SERVICE_UID, SERVICE_GID):
                    identity_verified = True
                    break
                if not identity.all_root:
                    raise StartupReadinessError("daemon identity mismatch")
            time.sleep(0.25)
        if not identity_verified:
            raise StartupReadinessError("daemon privilege-drop timeout")

        verify_attempt_socket_path(socket_path, readiness_root)
        _socket_command(
            runner, suricatasc=suricatasc, command="version",
            socket_path=socket_path, cwd=readiness_root,
        )
        stats = _socket_command(
            runner, suricatasc=suricatasc, command="ruleset-stats",
            socket_path=socket_path, cwd=readiness_root,
        )
        if not isinstance(stats, list) or len(stats) != 1 or stats[0].get("rules_loaded") != 0:
            raise StartupReadinessError("startup readiness ruleset was not empty")
        socket_verified = True
    except Exception as exc:
        startup_error = exc
    finally:
        if process is not None:
            try:
                if process.poll() is None:
                    try:
                        _socket_command(
                            runner, suricatasc=suricatasc, command="shutdown",
                            socket_path=socket_path, cwd=readiness_root,
                        )
                        process.wait(timeout=20)
                    except (Exception, subprocess.TimeoutExpired):
                        pass
                if process.poll() is None:
                    _terminate_and_verify(process)
            finally:
                for collector in output_collectors:
                    collector.close()
        process_stopped = process is None or process.poll() is not None
        if process_stopped and transaction is not None:
            try:
                remove_attempt_acls(access_paths, transaction=transaction, runner=runner)
                cleanup_verified = True
            except PrivilegeSeparationError:
                cleanup_verified = False
        if process_stopped and cleanup_verified:
            pidfile.unlink(missing_ok=True)
            socket_path.unlink(missing_ok=True)
            active_rules.unlink(missing_ok=True)

    diagnostics = {
        "stdout": output_collectors[0].text() if output_collectors else "",
        "stderr": output_collectors[1].text() if len(output_collectors) > 1 else "",
    }
    result = {
        "schema_version": "g5_startup_readiness_v1",
        "status": "READY_FOR_OWNER_REVIEW" if startup_error is None and cleanup_verified else "FAILED",
        "live_startup_performed": process is not None,
        "candidate_activation_attempted": False,
        "traffic_replay_attempted": False,
        "authorization_consumed": False,
        "nonce_consumed": False,
        "attempt_id": attempt_id,
        "readiness_root": str(readiness_root),
        "effective_config": str(effective_config),
        "active_rules": str(active_rules),
        "control_socket": str(socket_path),
        "identity_verified": identity_verified,
        "socket_verified": socket_verified,
        "process_stopped": process is None or process.poll() is not None,
        "acl_cleanup_verified": cleanup_verified,
        "diagnostics": diagnostics,
        "error": _redact_diagnostic(startup_error) if startup_error else None,
    }
    report = Path(report_path) if report_path is not None else readiness_root / "startup-readiness.json"
    if not report.resolve().is_relative_to(readiness_root.resolve()):
        raise StartupReadinessError("readiness report must remain inside readiness namespace")
    _write_exclusive(report, result)
    if startup_error is not None:
        raise StartupReadinessError(str(startup_error)) from startup_error
    if not cleanup_verified:
        raise StartupReadinessError("startup readiness cleanup was not verified")
    return result


def main(argv=None) -> int:
    supplied = list(sys.argv[1:] if argv is None else argv)
    require_startup_smoke_guard(supplied, os.environ)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute-startup-smoke", action="store_true")
    parser.add_argument("--template-config", type=Path, required=True)
    parser.add_argument("--isolated-root", type=Path, required=True)
    parser.add_argument("--attempt-id", required=True)
    parser.add_argument("--suricata", default="/usr/bin/suricata")
    parser.add_argument("--suricatasc", default="/usr/bin/suricatasc")
    parser.add_argument("--setpriv", default="/usr/bin/setpriv")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(supplied)
    result = run_startup_readiness(
        template_config=args.template_config, isolated_root=args.isolated_root,
        attempt_id=args.attempt_id, suricata=args.suricata,
        suricatasc=args.suricatasc, setpriv=args.setpriv,
        report_path=args.report, guarded=True,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
