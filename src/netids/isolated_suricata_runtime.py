"""VM1-only, loopback-only Suricata 8.0.3 isolated runtime adapter.

This adapter has no SSH or production service control. It owns exactly one
subprocess launched with --af-packet=lo, a unique UNIX socket and an isolated
-S exclusive rules file. It refuses to report ACTIVE without a real EVE SID
alert after tcpreplay on lo and refuses to report rollback without replaying
the same PCAP with zero candidate SID alerts.
"""

from __future__ import annotations

import json
import hashlib
import os
import re
import socket
import struct
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml

from netids.lifecycle_ed25519 import sha256_file
from netids.privilege_separation import (
    AttemptAccessPaths, PrivilegeSeparationError, SERVICE_GID, SERVICE_GROUP,
    SERVICE_UID, SERVICE_USER, apply_attempt_acls,
    atomic_replace_with_acl, confine_configuration_references,
    lookup_service_account, read_process_identity, referenced_configuration_files,
    prepare_runtime_output_files, remove_attempt_acls, require_root_operator_if_supported,
    verify_attempt_socket_path,
)
from netids.trusted_replay import SID, RULE_SHA, _config_safe

PROBE_OBSERVATION_SECONDS = 15.0
PROBE_BASELINE_SECONDS = 15.0

# Logical approval identity remains "suricata-vm1"; the lab VM's
# observed actual OS hostname is "tanhv", with ens33 = 192.168.10.10/24.
# Require BOTH invariants, rather than weakening the VM1-only guard.
VM1_HOST = "suricata-vm1"
VM1_OS_HOSTNAME = "tanhv"
VM1_INTERFACE = "ens33"
VM1_INTERFACE_CIDR = "192.168.10.10/24"
ROOT = Path("/home/tanhv/suricata-rule-review/isolated-lifecycle-9103003")
DIAGNOSTIC_MAX_BYTES = 64 * 1024
DIAGNOSTIC_FIELD_MAX_BYTES = 4096
_PRIVATE_KEY = re.compile(
    r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
    re.DOTALL,
)
_SECRET_FIELD = re.compile(
    r"(?i)(password|passphrase|private[_ -]?key|secret|token|credential)(\s*[:=]\s*)\S+",
)
_ATTEMPT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
SURICATA_YAML_HEADER = "%YAML 1.1\n---\n"
LINUX_UNIX_SOCKET_PATH_MAX_BYTES = 107


def validate_attempt_id(attempt_id: str) -> str:
    if not isinstance(attempt_id, str) or not _ATTEMPT_ID.fullmatch(attempt_id):
        raise ValueError("Invalid attempt-specific evidence identifier")
    return attempt_id


def validate_unix_socket_path(path: Path) -> Path:
    encoded = os.fsencode(os.fspath(path))
    if len(encoded) > LINUX_UNIX_SOCKET_PATH_MAX_BYTES:
        raise ValueError(
            "UNIX socket pathname exceeds Linux limit "
            f"({len(encoded)} > {LINUX_UNIX_SOCKET_PATH_MAX_BYTES} bytes)"
        )
    return Path(path)


def validate_isolated_configuration(
    configuration: dict, *, active_rules: Path, socket_path: Path,
) -> None:
    if not isinstance(configuration, dict):
        raise ValueError("Isolated Suricata configuration is not an object")
    unix_command = configuration.get("unix-command")
    if not isinstance(unix_command, dict) or unix_command.get("enabled") is not True:
        raise ValueError("Isolated UNIX socket is not enabled in configuration")
    configured_socket = Path(str(unix_command.get("filename", "")))
    validate_unix_socket_path(configured_socket)
    validate_unix_socket_path(socket_path)
    if configured_socket.resolve() != socket_path.resolve():
        raise ValueError("Isolated UNIX socket path is not attempt-specific")

    rule_files = configuration.get("rule-files")
    if not isinstance(rule_files, list) or len(rule_files) != 1 or not isinstance(rule_files[0], str):
        raise ValueError("Isolated configuration must reference exactly one ruleset")
    default_rule_path = configuration.get("default-rule-path", ".")
    configured_rules = Path(rule_files[0])
    if not configured_rules.is_absolute():
        configured_rules = Path(default_rule_path) / configured_rules
    if configured_rules.resolve() != active_rules.resolve():
        raise ValueError("Isolated configuration references a non-isolated ruleset")

    captures = configuration.get("af-packet", [])
    if not isinstance(captures, list) or not captures or any(
        not isinstance(entry, dict) or entry.get("interface") != "lo" for entry in captures
    ):
        raise ValueError("Isolated configuration must capture loopback only")


def generate_effective_suricata_configuration(
    template: Path | dict, *, active_rules: Path, socket_path: Path,
) -> str:
    if isinstance(template, dict):
        configuration = dict(template)
    else:
        try:
            configuration = yaml.safe_load(Path(template).read_text(encoding="utf-8"))
        except (OSError, UnicodeError, yaml.YAMLError) as exc:
            raise ValueError("Invalid isolated Suricata configuration template") from exc
    if not isinstance(configuration, dict):
        raise ValueError("Isolated Suricata configuration template is not an object")
    if configuration.get("unix-command") is not None and not isinstance(
        configuration.get("unix-command"), dict
    ):
        raise ValueError("Isolated UNIX command configuration is invalid")
    configuration["default-rule-path"] = str(Path(active_rules).parent)
    configuration["rule-files"] = ["active.rules"]
    unix_command = dict(configuration.get("unix-command") or {})
    unix_command["enabled"] = True
    unix_command["filename"] = str(validate_unix_socket_path(socket_path))
    configuration["unix-command"] = unix_command
    validate_isolated_configuration(
        configuration, active_rules=Path(active_rules), socket_path=Path(socket_path),
    )
    return SURICATA_YAML_HEADER + yaml.safe_dump(configuration, sort_keys=False) + "\n"


def validate_attempt_namespace(root: Path, attempt_id: str) -> tuple[Path, Path]:
    """Validate future namespace and socket before lifecycle or authorization use."""
    attempt_id = validate_attempt_id(attempt_id)
    root = Path(root)
    attempt_root = root / "attempts" / attempt_id
    socket_path = attempt_root / "runtime" / "lab-suricata.socket"
    validate_unix_socket_path(socket_path)
    resolved_root = root.resolve()
    if not root.is_dir() or root.is_symlink():
        raise ValueError("Exact isolated runtime root is missing/unsafe")
    attempts = root / "attempts"
    if attempts.is_symlink():
        raise ValueError("Attempt evidence directory is symlinked")
    if attempt_root.exists() or attempt_root.is_symlink():
        raise ValueError("Attempt evidence namespace already exists; refuse reuse")
    if not attempt_root.resolve().is_relative_to(resolved_root):
        raise ValueError("Attempt evidence namespace escapes isolated root")
    return attempt_root, socket_path


def _redact_diagnostic(value: object) -> str:
    """Keep native diagnostics useful without retaining credential material."""
    text = str(value)
    text = _PRIVATE_KEY.sub("[REDACTED_PRIVATE_KEY]", text)
    text = _SECRET_FIELD.sub(r"\1\2[REDACTED]", text)
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) > DIAGNOSTIC_FIELD_MAX_BYTES:
        text = encoded[:DIAGNOSTIC_FIELD_MAX_BYTES].decode("utf-8", errors="ignore")
        text += "…[TRUNCATED]"
    return text


class _BoundedProcessOutput:
    """Drain a child pipe continuously while retaining only a bounded tail."""

    def __init__(self, stream):
        self._stream = stream
        self._buffer = bytearray()
        self._truncated = False
        self._lock = threading.Lock()
        self._thread = None
        if stream is not None:
            self._thread = threading.Thread(target=self._drain, daemon=True)
            self._thread.start()

    def _drain(self):
        try:
            while True:
                chunk = self._stream.read(4096)
                if not chunk:
                    return
                if isinstance(chunk, str):
                    chunk = chunk.encode("utf-8", errors="replace")
                with self._lock:
                    available = DIAGNOSTIC_FIELD_MAX_BYTES - len(self._buffer)
                    if available > 0:
                        self._buffer.extend(chunk[:available])
                    if len(chunk) > available:
                        self._truncated = True
        except (OSError, ValueError):
            return

    def text(self) -> str:
        with self._lock:
            value = bytes(self._buffer).decode("utf-8", errors="replace")
            if self._truncated:
                value += "…[TRUNCATED]"
            return _redact_diagnostic(value)

    def close(self):
        if self._thread is not None:
            self._thread.join(timeout=1)


def is_verified_vm1_host() -> bool:
    """Read-only host and exact ens33 IPv4 check; false on any uncertainty."""
    if socket.gethostname() != VM1_OS_HOSTNAME:
        return False
    try:
        check = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", "dev", VM1_INTERFACE],
            capture_output=True, text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    if check.returncode != 0:
        return False
    expected = re.escape(VM1_INTERFACE_CIDR)
    return re.search(r"\binet\s+" + expected + r"(?=\s|$)", check.stdout) is not None


class IsolatedRuntimeError(RuntimeError):
    pass


def _run(
    argv: list[str], *, timeout: int = 60, deadline_monotonic=None,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess:
    if deadline_monotonic is not None:
        remaining = deadline_monotonic - time.monotonic()
        if remaining <= 0:
            raise IsolatedRuntimeError("Isolated runtime deadline exceeded")
        timeout = min(timeout, max(1, int(remaining)))
    try:
        result = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, check=False, cwd=cwd,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        output = ""
        if isinstance(exc, subprocess.TimeoutExpired):
            output = _redact_diagnostic(
                f" stdout={getattr(exc, 'stdout', '')!r} stderr={getattr(exc, 'stderr', '')!r}"
            )
        raise IsolatedRuntimeError(f"Isolated command failed or timed out{output}") from exc
    if result.returncode:
        details = _redact_diagnostic(
            f" stdout={result.stdout!r} stderr={result.stderr!r}"
        )
        raise IsolatedRuntimeError(
            f"Isolated command returned a nonzero status ({result.returncode});{details}"
        )
    return result


def _atomic(path: Path, data: bytes) -> None:
    fd, name = tempfile.mkstemp(prefix=".isolated-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


class IsolatedSuricataRuntime:
    """Trusted runtime only if called by the owner-authorized VM1 CLI."""

    def __init__(
        self, *, config: Path, attack_pcap: Path, attack_sha256: str,
        normal_pcap: Path, normal_sha256: str, suricata="/usr/bin/suricata",
        suricatasc="/usr/bin/suricatasc", tcpreplay="/usr/bin/tcpreplay",
        candidate_sid: int = SID, candidate_rule_sha256: str = RULE_SHA,
        root: Path = ROOT, attempt_id: str | None = None,
        negative_pcaps=(), negative_sha256s=(), probe_plan=(),
        deadline_monotonic=None, latency_trace=None,
    ):
        self.root = Path(root)
        self.config_source = Path(config)
        try:
            self.attempt_id = validate_attempt_id(attempt_id) if attempt_id is not None else None
        except ValueError as exc:
            raise IsolatedRuntimeError(str(exc)) from exc
        self.attempt_root = (
            self.root / "attempts" / self.attempt_id
            if self.attempt_id is not None else self.root
        )
        self.sid = candidate_sid
        self.rule_sha256 = candidate_rule_sha256
        self.config = (
            self.attempt_root / "suricata.yaml"
            if self.attempt_id is not None else self.config_source
        )
        self.attack_pcap = Path(attack_pcap)
        self.normal_pcap = Path(normal_pcap)
        self.attack_sha256 = attack_sha256
        self.normal_sha256 = normal_sha256
        self.negative_pcaps = tuple(Path(path) for path in negative_pcaps)
        self.negative_sha256s = tuple(negative_sha256s)
        self.probe_plan = tuple(dict(probe) for probe in probe_plan)
        self.deadline_monotonic = deadline_monotonic
        self.latency_trace = latency_trace
        self.suricata = str(suricata)
        self.suricatasc = str(suricatasc)
        self.tcpreplay = str(tcpreplay)
        self.service_user = SERVICE_USER
        self.service_group = SERVICE_GROUP
        self.expected_uid = SERVICE_UID
        self.expected_gid = SERVICE_GID
        self.service_account = None
        self._acl_paths = None
        self._acl_transaction = None
        self._referenced_files = ()
        self.socket_path = self.attempt_root / "runtime" / "lab-suricata.socket"
        self.pidfile = self.attempt_root / "runtime" / "lab-suricata.pid"
        self.active_rules = self.attempt_root / "rules" / "active.rules"
        self.logdir = self.attempt_root / "logs"
        self.validation_logdir = self.attempt_root / "validation-logs"
        self.diagnostic_path = self.attempt_root / "logs" / "runtime-diagnostics.jsonl"
        try:
            validate_unix_socket_path(self.socket_path)
        except ValueError as exc:
            raise IsolatedRuntimeError(str(exc)) from exc
        self.process = None
        self._output_collectors = []
        self._old_rules = None
        self._activated = False
        self.activation_attempted = False
        self.rollback_attempted = False
        self.rollback_verified = False
        self.post_rollback_verified = False
        self.failure_phase = None
        self.primary_failure_phase = None
        self.primary_failure_reason = None
        self._last_attack_eve = ""
        self.probe_results = []
        self._preflight()

    def _check_deadline(self):
        if self.deadline_monotonic is not None and time.monotonic() >= self.deadline_monotonic:
            raise IsolatedRuntimeError("Isolated runtime deadline exceeded")

    def _measure_bool(self, name: str, component: str, operation) -> bool:
        if self.latency_trace is None:
            return operation()
        with self.latency_trace.stage(name, component=component):
            result = operation()
        if result is False:
            self.latency_trace.stages[-1].update({
                "status": "error",
                "error_type": "operation_returned_false",
            })
        return result

    def _preflight(self) -> None:
        if not is_verified_vm1_host():
            raise IsolatedRuntimeError("Wrong host or ens33 address; isolated VM1 only")
        try:
            require_root_operator_if_supported()
            self.service_account = lookup_service_account(
                self.service_user, self.service_group,
            )
        except PrivilegeSeparationError as exc:
            raise IsolatedRuntimeError(str(exc)) from exc
        if not self.root.is_dir() or self.root.is_symlink():
            raise IsolatedRuntimeError("Exact isolated runtime root is missing/unsafe")
        if self.attempt_id is None:
            raise IsolatedRuntimeError("Attempt-specific evidence identifier is required")
        if not Path("/sys/class/net/lo").exists():
            raise IsolatedRuntimeError("Loopback interface is unavailable")
        self._prepare_attempt_namespace()
        _config_safe(self.config, self.root)
        self._validate_isolated_configuration()
        if len(self.negative_pcaps) != len(self.negative_sha256s):
            raise IsolatedRuntimeError("Negative-control PCAP/hash counts differ")
        pinned_pcaps = [
            (self.attack_pcap, self.attack_sha256),
            (self.normal_pcap, self.normal_sha256),
            *zip(self.negative_pcaps, self.negative_sha256s),
        ]
        for probe in self.probe_plan:
            if not isinstance(probe.get("case"), str) or probe.get("label") not in ("ATTACK", "NORMAL"):
                raise IsolatedRuntimeError("Invalid signed probe plan")
            pinned_pcaps.append((Path(probe["path"]), probe.get("pcap_sha256")))
        for file, expected in pinned_pcaps:
            if file.is_symlink() or not file.is_file() or sha256_file(file) != expected:
                raise IsolatedRuntimeError("Pinned replay PCAP is missing or changed")
        for executable in (self.suricata, self.suricatasc, self.tcpreplay):
            if not Path(executable).is_file():
                raise IsolatedRuntimeError("Required preinstalled tool not available")
        version = _run([self.suricata, "-V"], timeout=20, deadline_monotonic=self.deadline_monotonic).stdout
        if "8.0.3" not in version:
            raise IsolatedRuntimeError("Suricata 8.0.3 is required")
        if self.socket_path.exists() or self.pidfile.exists():
            raise IsolatedRuntimeError("Isolated socket or PID exists; refuse shared runtime")
        for directory in (
            self.socket_path.parent, self.active_rules.parent, self.logdir,
            self.validation_logdir,
        ):
            if directory.is_symlink():
                raise IsolatedRuntimeError("Symlink directory in isolated runtime")
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.active_rules.exists():
            raise IsolatedRuntimeError("Unexpected existing isolated ruleset; refuse overwrite")
        try:
            configuration = yaml.safe_load(self.config.read_text(encoding="utf-8"))
            self._referenced_files = referenced_configuration_files(
                configuration, self.config, allowed_root=self.attempt_root,
            )
            runtime_output_files = prepare_runtime_output_files(configuration, self.logdir)
            self._acl_paths = AttemptAccessPaths(
                attempt_root=self.attempt_root, runtime_dir=self.socket_path.parent,
                rules_dir=self.active_rules.parent, active_rules=self.active_rules,
                logs_dir=self.logdir, effective_config=self.config,
                referenced_files=self._referenced_files,
                runtime_output_files=runtime_output_files,
            )
            self._acl_transaction = apply_attempt_acls(
                self._acl_paths, username=self.service_user,
            )
        except (OSError, UnicodeError, yaml.YAMLError, PrivilegeSeparationError) as exc:
            raise IsolatedRuntimeError("Attempt ACL preparation failed closed") from exc

    def _prepare_attempt_namespace(self) -> None:
        """Create one exclusive runtime evidence namespace without touching prior attempts."""
        if self.attempt_id is None:
            raise IsolatedRuntimeError("Attempt-specific evidence identifier is required")
        try:
            validate_attempt_namespace(self.root, self.attempt_id)
        except ValueError as exc:
            raise IsolatedRuntimeError(str(exc)) from exc
        if self.config_source.is_symlink() or not self.config_source.is_file():
            raise IsolatedRuntimeError("Isolated configuration template is missing or unsafe")
        _config_safe(self.config_source, self.root)

        attempts = self.root / "attempts"
        attempts.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.attempt_root.exists() or self.attempt_root.is_symlink():
            raise IsolatedRuntimeError("Attempt evidence namespace already exists; refuse reuse")
        self.attempt_root.mkdir(mode=0o700)
        for directory in (
            self.socket_path.parent, self.active_rules.parent, self.logdir,
            self.validation_logdir,
        ):
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)

        try:
            template = yaml.safe_load(self.config_source.read_text(encoding="utf-8"))
            confined = confine_configuration_references(
                template, self.config_source, attempt_root=self.attempt_root,
                allowed_root=self.root,
            )
            effective = generate_effective_suricata_configuration(
                confined, active_rules=self.active_rules, socket_path=self.socket_path,
            )
            _atomic(self.config, effective.encode("utf-8"))
        except (OSError, UnicodeError, TypeError, ValueError, yaml.YAMLError, PrivilegeSeparationError) as exc:
            raise IsolatedRuntimeError("Could not create effective attempt configuration") from exc

    def _validate_isolated_configuration(self) -> None:
        try:
            configuration = yaml.safe_load(self.config.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, yaml.YAMLError) as exc:
            raise IsolatedRuntimeError("Invalid isolated Suricata configuration") from exc
        try:
            validate_isolated_configuration(
                configuration, active_rules=self.active_rules,
                socket_path=self.socket_path,
            )
        except ValueError as exc:
            raise IsolatedRuntimeError(str(exc)) from exc

    def _record_diagnostic(self, phase: str, **details) -> None:
        """Append bounded, redacted structured diagnostics; never mask the failure."""
        if details.get("status") == "failed":
            if getattr(self, "failure_phase", None) is None:
                self.failure_phase = phase
            if getattr(self, "primary_failure_phase", None) is None:
                self.primary_failure_phase = phase
                self.primary_failure_reason = str(details.get("error", "unknown failure"))
        try:
            self.diagnostic_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if self.diagnostic_path.exists() and self.diagnostic_path.stat().st_size >= DIAGNOSTIC_MAX_BYTES:
                return
            record = {
                "timestamp": time.time(),
                "phase": phase,
                **{key: _redact_diagnostic(value) if not isinstance(value, (bool, int, float)) else value
                   for key, value in details.items()},
            }
            line = json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n"
            remaining = DIAGNOSTIC_MAX_BYTES - self.diagnostic_path.stat().st_size if self.diagnostic_path.exists() else DIAGNOSTIC_MAX_BYTES
            if len(line.encode("utf-8")) > remaining:
                return
            with self.diagnostic_path.open("a", encoding="utf-8") as stream:
                stream.write(line)
                stream.flush()
                os.fsync(stream.fileno())
        except (OSError, UnicodeError, TypeError, ValueError):
            return

    def _process_output(self) -> dict:
        collectors = getattr(self, "_output_collectors", [])
        return {
            "stdout": collectors[0].text() if len(collectors) > 0 else "",
            "stderr": collectors[1].text() if len(collectors) > 1 else "",
        }

    def _close_process_output(self) -> dict:
        collectors = getattr(self, "_output_collectors", [])
        for collector in collectors:
            collector.close()
        return self._process_output()

    def _daemon_arguments(self) -> list[str]:
        """Build live arguments without selecting Suricata's UNIX_SOCKET run mode."""
        return [
            self.suricata, "-c", str(self.config), "-l", str(self.logdir), "--af-packet=lo",
            "--pidfile", str(self.pidfile), "--init-errors-fatal", "-k", "none",
            f"--user={getattr(self, 'service_user', SERVICE_USER)}",
            f"--group={getattr(self, 'service_group', SERVICE_GROUP)}",
        ]

    def _replace_active_rules(self, data: bytes) -> None:
        if getattr(self, "_acl_paths", None) is None:
            _atomic(self.active_rules, data)
            return
        atomic_replace_with_acl(
            self.active_rules, data, username=self.service_user,
            transaction=getattr(self, "_acl_transaction", None),
        )

    def _terminate_child(self) -> bool:
        process = self.process
        if process is None or process.poll() is not None:
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

    def _wait_for_privilege_drop(self, timeout: float = 15.0):
        """Wait for Suricata's documented post-initialization privilege drop."""
        if self.process is None:
            raise IsolatedRuntimeError("Suricata child is not started")
        deadline = time.monotonic() + max(0.0, timeout)
        last_error = None
        last_identity = None

        def identity_details(identity=None, error=None):
            details = {"pid": self.process.pid}
            if identity is not None:
                details.update({
                    "state": identity.state,
                    "uid_fields": identity.uid_fields,
                    "gid_fields": identity.gid_fields,
                    "supplementary_groups": identity.groups,
                    "cap_eff": identity.cap_eff,
                })
            if error is not None:
                details["identity_parser_error"] = str(error)
                observed = getattr(error, "observed_fields", {})
                if observed:
                    details.update(observed)
            return details

        while True:
            exit_status = self.process.poll()
            if exit_status is not None:
                self._record_diagnostic(
                    "startup", status="failed", error="daemon exited before privilege drop",
                    exit_status=exit_status, **identity_details(last_identity, last_error),
                )
                raise IsolatedRuntimeError("Suricata child exited before privilege drop")
            try:
                identity = read_process_identity(self.process.pid)
            except PrivilegeSeparationError as exc:
                identity = None
                last_error = exc
            if identity is not None:
                last_identity = identity
                if identity.is_expected(self.expected_uid, self.expected_gid):
                    self._record_diagnostic(
                        "startup", status="identity-verified", **identity_details(identity),
                    )
                    return identity
                if not identity.all_root:
                    detail = "unexpected non-root process identity"
                    self._record_diagnostic(
                        "startup", status="failed", error=detail,
                        **identity_details(identity),
                    )
                    if not self._terminate_child():
                        self._record_diagnostic(
                            "cleanup", status="failed",
                            error="identity-mismatch child termination unverified",
                        )
                    raise IsolatedRuntimeError(
                        f"Suricata child identity verification failed: {detail}"
                    )
            if time.monotonic() >= deadline:
                detail = str(last_error or "Suricata process remained privileged")
                details = identity_details(last_identity, last_error)
                details.update({
                    "error": "privilege drop timeout",
                    "first_causal_error": detail,
                    "exit_status": self.process.poll(),
                })
                self._record_diagnostic(
                    "startup", status="failed", **details,
                )
                if not self._terminate_child():
                    self._record_diagnostic(
                        "cleanup", status="failed",
                        error="privilege-drop timeout child termination unverified",
                    )
                raise IsolatedRuntimeError(
                    "Suricata privilege drop timeout; child identity was not accepted"
                )
            time.sleep(0.25)

    def _validation_rule_arguments(self, temporary: Path) -> list[str]:
        return [
            self.suricata, "-T", "--init-errors-fatal", "-c", str(self.config),
            "-S", str(temporary), "-l", str(self.validation_logdir),
        ]

    def _command(self, command: str) -> object:
        self._check_deadline()
        try:
            result = _run([
                self.suricatasc, "-c", command, str(self.socket_path)
            ], timeout=75, deadline_monotonic=self.deadline_monotonic, cwd=self.attempt_root)
        except IsolatedRuntimeError as exc:
            self._record_diagnostic("socket", status="failed", command=command, error=str(exc))
            raise
        try:
            output = json.loads(result.stdout)
        except ValueError as exc:
            self._record_diagnostic(
                "socket", status="failed", command=command,
                error="Suricata socket returned invalid JSON", stdout=result.stdout,
            )
            raise IsolatedRuntimeError("Suricata socket returned invalid JSON") from exc
        if not isinstance(output, dict) or output.get("return") != "OK":
            self._record_diagnostic(
                "socket", status="failed", command=command,
                error="Suricata UNIX command failed", response=output,
            )
            raise IsolatedRuntimeError("Suricata UNIX command failed")
        return output.get("message")

    def _rules_loaded(self, exact: int) -> bool:
        """Require authoritative runtime counts, not merely a rule file on disk."""
        stats = self._command("ruleset-stats")
        return (
            isinstance(stats, list)
            and len(stats) == 1
            and isinstance(stats[0], dict)
            and stats[0].get("rules_loaded") == exact
            and stats[0].get("rules_failed") == 0
            and stats[0].get("rules_skipped") == 0
        )

    def _start(self) -> None:
        self._check_deadline()
        if self.process is not None:
            raise IsolatedRuntimeError("Isolated daemon already owned")
        self._old_rules = b"# no active candidate rules in this isolated test\n"
        self._replace_active_rules(self._old_rules)
        arguments = self._daemon_arguments()
        self._record_diagnostic("startup", status="started", arguments=arguments)
        try:
            self.process = subprocess.Popen(
                arguments, cwd=self.attempt_root, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
            )
            self._output_collectors = [
                _BoundedProcessOutput(getattr(self.process, "stdout", None)),
                _BoundedProcessOutput(getattr(self.process, "stderr", None)),
            ]
        except (OSError, ValueError) as exc:
            self._record_diagnostic("startup", status="failed", error=str(exc))
            raise IsolatedRuntimeError("Suricata startup initialization failed") from exc
        if self.process.poll() is not None:
            output = self._close_process_output()
            self._record_diagnostic(
                "startup", status="failed", exit_status=self.process.poll(), **output,
            )
            raise IsolatedRuntimeError("Suricata startup failed: daemon exited during initialization")
        identity_timeout = 15.0
        if getattr(self, "deadline_monotonic", None) is not None:
            identity_timeout = min(
                identity_timeout,
                max(0.0, self.deadline_monotonic - time.monotonic()),
            )
        try:
            self._wait_for_privilege_drop(timeout=identity_timeout)
        except IsolatedRuntimeError as exc:
            output = self._close_process_output()
            self._record_diagnostic(
                "startup", status="failed", error=str(exc),
                exit_status=self.process.poll(), **output,
            )
            raise
        last_error = None
        socket_deadline = time.monotonic() + 10.0
        if getattr(self, "deadline_monotonic", None) is not None:
            socket_deadline = min(socket_deadline, self.deadline_monotonic)
        while time.monotonic() < socket_deadline:
            self._check_deadline()
            if self.process.poll() is not None:
                output = self._close_process_output()
                self._record_diagnostic(
                    "startup", status="failed", exit_status=self.process.poll(), **output,
                )
                raise IsolatedRuntimeError("Suricata startup failed: daemon exited during initialization")
            if self.socket_path.exists():
                try:
                    verify_attempt_socket_path(self.socket_path, self.attempt_root)
                    version = self._command("version")
                    if "8.0.3" in str(version):
                        mode = self._command("capture-mode")
                        if "AF_PACKET" not in str(mode):
                            raise IsolatedRuntimeError("Wrong isolated capture mode")
                        if not self._rules_loaded(0):
                            raise IsolatedRuntimeError("Isolated baseline is not an empty ruleset")
                        self._record_diagnostic("startup", status="ready", capture_mode=str(mode))
                        return
                except IsolatedRuntimeError as exc:
                    last_error = exc
            time.sleep(0.25)
        output = self._process_output()
        self._record_diagnostic(
            "startup", status="failed", error=str(last_error or "socket was not ready"), **output,
        )
        if not self._terminate_child():
            self._record_diagnostic(
                "cleanup", status="failed",
                error="socket-readiness timeout child termination unverified",
            )
        raise IsolatedRuntimeError(
            f"Isolated UNIX socket was not ready: {last_error or 'startup timeout'}"
        )

    def _pcap_probe(self, file: Path, *, expect_alert: bool, case=None, label=None, scenario=None, phase="active") -> bool:
        stage_name = f"probe_{phase}_{case or file.stem}"
        return self._measure_bool(
            stage_name, "runtime", lambda: self._pcap_probe_impl(
                file, expect_alert=expect_alert, case=case, label=label,
                scenario=scenario, phase=phase,
            ),
        )

    @staticmethod
    def _eve_timestamp(record):
        value = record.get("timestamp")
        if not isinstance(value, str):
            raise ValueError("EVE timestamp is missing")
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("EVE timestamp has no timezone")
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _eve_records(path: Path, offset: int):
        """Read only newline-terminated JSONL records, retaining a partial tail."""
        if not path.is_file():
            return [], offset, offset
        with path.open("rb") as stream:
            stream.seek(offset)
            data = stream.read()
        records = []
        consumed = 0
        for line in data.splitlines(keepends=True):
            if not line.endswith(b"\n"):
                break
            consumed += len(line)
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except (UnicodeError, ValueError) as exc:
                raise ValueError("malformed complete EVE JSON record") from exc
            if not isinstance(record, dict):
                raise ValueError("EVE record is not an object")
            records.append((record, offset + consumed))
        return records, offset + consumed, offset + len(data)

    @classmethod
    def _stats_counters(cls, record):
        if record.get("event_type") != "stats":
            return None
        stats = record.get("stats")
        if not isinstance(stats, dict):
            raise ValueError("stats event body is missing")
        counters = {}
        for name, section in (("capture.kernel_packets", "capture"), ("decoder.pkts", "decoder")):
            value = stats.get(section, {}).get(name.split(".", 1)[1]) if isinstance(stats.get(section), dict) else None
            if type(value) is not int or value < 0:
                raise ValueError(f"stats counter {name} is missing or invalid")
            counters[name] = value
        return counters

    @staticmethod
    def _pcap_flow_set(path: Path):
        """Return canonical bidirectional IPv4 TCP/UDP flows from a classic PCAP."""
        digest = sha256_file(path)
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest or len(raw) < 24:
            raise ValueError("probe PCAP changed or is truncated")
        magic = raw[:4]
        endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">" if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d") else None
        if endian is None:
            raise ValueError("unsupported probe PCAP format")
        linktype = struct.unpack_from(endian + "I", raw, 20)[0]
        if linktype != 1:
            raise ValueError("probe PCAP link type is not Ethernet")
        flows, pos = set(), 24
        while pos < len(raw):
            if len(raw) - pos < 16:
                raise ValueError("truncated probe PCAP packet header")
            _, _, caplen, wirelen = struct.unpack_from(endian + "IIII", raw, pos)
            pos += 16
            if caplen > wirelen or pos + caplen > len(raw):
                raise ValueError("truncated probe PCAP packet")
            frame = raw[pos:pos + caplen]
            pos += caplen
            if len(frame) < 14:
                raise ValueError("truncated Ethernet frame in probe PCAP")
            if struct.unpack_from("!H", frame, 12)[0] != 0x0800:
                raise ValueError("probe PCAP contains an unsupported Ethernet protocol")
            ip = frame[14:]
            if len(ip) < 20 or ip[0] >> 4 != 4:
                raise ValueError("probe PCAP contains a truncated or unsupported IP packet")
            ihl = (ip[0] & 15) * 4
            if ihl < 20 or len(ip) < ihl:
                raise ValueError("malformed IPv4 packet in probe PCAP")
            total_len = struct.unpack_from("!H", ip, 2)[0]
            if total_len < ihl or total_len > len(ip):
                raise ValueError("truncated IPv4 payload in probe PCAP")
            proto = ip[9]
            if proto not in (6, 17):
                raise ValueError("probe PCAP contains an unsupported transport protocol")
            if struct.unpack_from("!H", ip, 6)[0] & 0x3fff:
                raise ValueError("fragmented probe packet cannot be correlated")
            if len(ip) < ihl + 4:
                raise ValueError("truncated transport header in probe PCAP")
            src, dst = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
            sport, dport = struct.unpack_from("!HH", ip, ihl)
            ends = sorted(((src, sport), (dst, dport)))
            flows.add((proto, ends[0][0], ends[0][1], ends[1][0], ends[1][1]))
        if not flows:
            raise ValueError("probe PCAP has no correlatable TCP/UDP flows")
        return digest, flows

    @staticmethod
    def _eve_flow_tuple(record):
        try:
            proto = {"TCP": 6, "UDP": 17}.get(record.get("proto", "").upper())
            if proto is None:
                return None
            ends = sorted(((str(record["src_ip"]), int(record["src_port"])), (str(record["dest_ip"]), int(record["dest_port"]))))
            if any(not 0 <= p <= 65535 for _, p in ends):
                return None
            return (proto, ends[0][0], ends[0][1], ends[1][0], ends[1][1])
        except (KeyError, TypeError, ValueError, AttributeError):
            return None

    def _pcap_probe_impl(self, file: Path, *, expect_alert: bool, case=None, label=None, scenario=None, phase="active") -> bool:
        started = time.monotonic()
        result = {
            "case": case, "label": label, "scenario": scenario, "phase": phase,
            "pcap_sha256": None, "expected_alert": expect_alert,
            "candidate_alerts": 0, "result": False, "outcome": "FAIL",
            "failure_reason": "probe_observation_incomplete", "traffic_proof": None,
            "evidence_correlation_id": None,
            "counter_baseline": None, "counter_delta": None,
            "counter_baseline_eve_offset": None,
            "eve_offset_start": None, "eve_offset_end": None,
            "replay_started_at": None, "replay_ended_at": None,
            "observation_started_at": None,
            "observation_ended_at": None, "clock_type": "monotonic",
        }
        candidate_alerts = 0
        candidate_alert_flow_ids = set()
        candidate_alert_events = []
        eve = self.logdir / "eve.json"
        try:
            self._check_deadline()
            result["pcap_sha256"], expected_flows = self._pcap_flow_set(file)
            planned = next((item for item in self.probe_plan if item.get("case") == case), None)
            if planned is None or planned.get("pcap_sha256") != result["pcap_sha256"]:
                raise ValueError("probe PCAP does not match frozen probe plan")
            baseline_deadline = time.monotonic() + PROBE_BASELINE_SECONDS
            if self.deadline_monotonic is not None:
                baseline_deadline = min(baseline_deadline, self.deadline_monotonic)
            cursor = 0
            baseline_record = None
            last_baseline_time = None
            last_baseline_counters = None
            while time.monotonic() < baseline_deadline:
                if not eve.is_file():
                    raise ValueError("EVE file is missing")
                records, cursor, _ = self._eve_records(eve, cursor)
                for record, record_end in records:
                    counters = self._stats_counters(record)
                    if counters is not None:
                        stats_time = self._eve_timestamp(record)
                        if last_baseline_time is not None and (
                            stats_time < last_baseline_time
                            or any(counters[key] < last_baseline_counters[key] for key in counters)
                        ):
                            raise ValueError("pre-replay Suricata counters reset or timestamp regressed")
                        last_baseline_time, last_baseline_counters = stats_time, counters
                        baseline_record = (stats_time, counters, record_end)
                if baseline_record is None:
                    time.sleep(min(0.1, max(0.0, baseline_deadline - time.monotonic())))
                else:
                    # Re-drain immediately before replay so the selected baseline
                    # is the latest complete valid pre-replay stats sample.
                    latest, cursor, _ = self._eve_records(eve, cursor)
                    for record, record_end in latest:
                        counters = self._stats_counters(record)
                        if counters is not None:
                            stats_time = self._eve_timestamp(record)
                            if stats_time < last_baseline_time or any(counters[k] < last_baseline_counters[k] for k in counters):
                                raise ValueError("pre-replay Suricata counters reset or timestamp regressed")
                            last_baseline_time, last_baseline_counters = stats_time, counters
                            baseline_record = (stats_time, counters, record_end)
                    break
            if baseline_record is None:
                raise ValueError("valid pre-replay stats baseline was not observed")
            baseline_time, baseline, baseline_eve_offset = baseline_record
            replay_start = datetime.now(timezone.utc)
            if baseline_time > replay_start:
                raise ValueError("pre-replay stats timestamp is in the future")
            result["counter_baseline"] = dict(baseline)
            result["counter_baseline_eve_offset"] = baseline_eve_offset
            result["replay_started_at"] = replay_start.isoformat()
            result["eve_offset_start"] = cursor
            _run([
                self.tcpreplay, "--intf1=lo", "--pps=150", str(file),
            ], timeout=180, deadline_monotonic=self.deadline_monotonic)
            replay_end = datetime.now(timezone.utc)
            result["replay_ended_at"] = replay_end.isoformat()
            observation_deadline = time.monotonic() + PROBE_OBSERVATION_SECONDS
            if self.deadline_monotonic is not None:
                observation_deadline = min(observation_deadline, self.deadline_monotonic)
            result["observation_started_at"] = replay_end.isoformat()
            cursor = result["eve_offset_start"]
            traffic_stats = None
            previous_counters = baseline
            matched_flows = set()
            flow_ids = {}
            while time.monotonic() < observation_deadline:
                self._check_deadline()
                records, cursor, current_end = self._eve_records(eve, cursor)
                result["eve_offset_end"] = current_end
                for record, record_end in records:
                    stats_counters = self._stats_counters(record)
                    timestamp = self._eve_timestamp(record) if isinstance(record.get("timestamp"), str) else None
                    if stats_counters is not None and timestamp >= replay_start:
                        if any(stats_counters[key] < previous_counters[key] for key in previous_counters):
                            raise ValueError("Suricata counters reset during probe observation")
                        previous_counters = stats_counters
                        if timestamp > replay_end:
                            traffic_stats = stats_counters
                    flow_tuple = self._eve_flow_tuple(record)
                    flow_id = record.get("flow_id")
                    if record.get("event_type") == "flow" and timestamp is not None and timestamp > replay_start and flow_tuple in expected_flows and type(flow_id) is int:
                        matched_flows.add(flow_tuple)
                        flow_ids.setdefault(flow_tuple, set()).add(flow_id)
                    if record.get("event_type") == "alert":
                        alert = record.get("alert")
                        if not isinstance(alert, dict) or type(alert.get("signature_id")) is not int:
                            raise ValueError("alert event has invalid signature identity")
                        if timestamp is not None and replay_start <= timestamp <= datetime.now(timezone.utc) and alert["signature_id"] == self.sid:
                            candidate_alerts += 1
                            candidate_alert_events.append((flow_tuple, flow_id))
                time.sleep(min(0.1, max(0.0, observation_deadline - time.monotonic())))
            if traffic_stats is None:
                raise ValueError("post-replay auxiliary stats sample was not observed")
            delta = {key: traffic_stats[key] - baseline[key] for key in baseline}
            if any(value < 0 for value in delta.values()):
                raise ValueError("Suricata counters reset during probe observation")
            if any(value == 0 for value in delta.values()):
                raise ValueError("post-replay auxiliary stats show no counter liveness")
            result["counter_delta"] = delta
            if matched_flows != expected_flows:
                raise ValueError("probe-specific PCAP/EVE flow correlation is incomplete")
            for flow_tuple, flow_id in candidate_alert_events:
                if flow_tuple not in expected_flows:
                    raise ValueError("candidate alert belongs to unrelated probe flow")
                if type(flow_id) is int and flow_id in flow_ids.get(flow_tuple, set()):
                    candidate_alert_flow_ids.add(flow_id)
            flow_hash = hashlib.sha256(json.dumps(sorted(expected_flows), separators=(",", ":")).encode()).hexdigest()
            flow_id_hash = hashlib.sha256(json.dumps(sorted({fid for ids in flow_ids.values() for fid in ids})).encode()).hexdigest()
            result["traffic_proof"] = {
                "type": "pcap_eve_flow_tuple_correlation_v1",
                "pcap_flow_set_sha256": flow_hash,
                "expected_flow_count": len(expected_flows),
                "matched_flow_count": len(matched_flows),
                "flow_id_set_sha256": flow_id_hash,
            }
            result["evidence_correlation_id"] = hashlib.sha256(
                f"{case}:{result['pcap_sha256']}:{flow_hash}:{flow_id_hash}".encode()
            ).hexdigest()
            if expect_alert and not candidate_alert_flow_ids:
                raise ValueError("candidate_alert_expectation_mismatch")
            if not expect_alert and candidate_alerts:
                raise ValueError("candidate_alert_expectation_mismatch")
            result["candidate_alerts"] = candidate_alerts
            result["failure_reason"] = None
            result["result"] = True
            result["outcome"] = "PASS"
            if expect_alert:
                self._last_attack_eve = sha256_file(eve)
            return True
        except (IsolatedRuntimeError, OSError, UnicodeError, ValueError, TypeError) as exc:
            result["failure_reason"] = str(exc) if isinstance(exc, ValueError) else "probe_observation_error"
            return False
        finally:
            result["candidate_alerts"] = candidate_alerts
            result["observation_ended_at"] = datetime.now(timezone.utc).isoformat()
            result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
            try:
                if eve.is_file():
                    result["eve_offset_end"] = eve.stat().st_size
            except OSError:
                pass
            self.probe_results.append(result)

    def validate(self, rule: str) -> bool:
        return self._measure_bool(
            "candidate_rule_validation", "hybrid", lambda: self._validate_impl(rule)
        )

    def _validate_impl(self, rule: str) -> bool:
        self._check_deadline()
        if not rule.startswith("alert tcp ") or "\n" in rule or "\r" in rule:
            return False
        if sha256_file(self.attack_pcap) != self.attack_sha256:
            return False
        directory = self.attempt_root / "runtime"
        temporary = directory / "validate-candidate.rules"
        if temporary.exists():
            return False
        try:
            _atomic(temporary, rule.encode("utf-8") + b"\n")
            result = _run(
                self._validation_rule_arguments(temporary),
                timeout=120, deadline_monotonic=self.deadline_monotonic,
                cwd=self.attempt_root,
            )
            return result.returncode == 0
        except IsolatedRuntimeError as exc:
            self._record_diagnostic("syntax_validation", status="failed", error=str(exc))
            return False
        finally:
            temporary.unlink(missing_ok=True)

    def activate(self, destination: Path, sid: int, rule_sha256: str) -> bool:
        return self._measure_bool(
            "isolated_runtime_activation", "runtime",
            lambda: self._activate_impl(destination, sid, rule_sha256),
        )

    def _activate_impl(self, destination: Path, sid: int, rule_sha256: str) -> bool:
        self.activation_attempted = True
        if sid != self.sid or rule_sha256 != self.rule_sha256:
            return False
        source = Path(destination)
        if source.is_symlink() or sha256_file(source) != rule_sha256:
            return False
        try:
            self._start()
            self._replace_active_rules(source.read_bytes())
            try:
                self._command("ruleset-reload-rules")
            except IsolatedRuntimeError as exc:
                self._record_diagnostic("reload", status="failed", error=str(exc))
                raise
            if not self._rules_loaded(1):
                raise IsolatedRuntimeError("Exact candidate rule not confirmed loaded")
            self._activated = True
            return True
        except (IsolatedRuntimeError, OSError) as exc:
            self._record_diagnostic("activation", status="failed", error=str(exc))
            return False

    def verify_active(self, sid: int, rule_sha256: str) -> bool:
        return self._measure_bool(
            "probe_verification_active", "runtime",
            lambda: self._verify_active_impl(sid, rule_sha256),
        )

    def _verify_active_impl(self, sid: int, rule_sha256: str) -> bool:
        if (
            sid != self.sid or rule_sha256 != self.rule_sha256 or not self._activated
            or self.process is None or self.process.poll() is not None
            or sha256_file(self.active_rules) != self.rule_sha256
        ):
            if self.probe_plan:
                self._record_not_run("active", "active runtime prerequisites failed")
            return False
        try:
            if not self._rules_loaded(1):
                if self.probe_plan:
                    self._record_not_run("active", "candidate ruleset was not verified")
                return False
            if self.probe_plan:
                return self._run_probe_plan("active", stop_on_failure=True)
            outcomes = [
                self._pcap_probe(self.attack_pcap, expect_alert=True),
                self._pcap_probe(self.normal_pcap, expect_alert=False),
            ]
            outcomes.extend(self._pcap_probe(path, expect_alert=False) for path in self.negative_pcaps)
            return all(outcomes)
        except (IsolatedRuntimeError, OSError):
            if self.probe_plan:
                self._record_not_run("active", "active verification stopped after runtime error")
            return False

    def rollback(self, destination: Path, sid: int, rule_sha256: str) -> bool:
        return self._measure_bool(
            "mandatory_rollback", "runtime",
            lambda: self._rollback_impl(destination, sid, rule_sha256),
        )

    def _rollback_impl(self, destination: Path, sid: int, rule_sha256: str) -> bool:
        self.rollback_attempted = True
        if sid != self.sid or rule_sha256 != self.rule_sha256 or self.process is None:
            return False
        try:
            self._replace_active_rules(self._old_rules)
            try:
                self._command("ruleset-reload-rules")
            except IsolatedRuntimeError as exc:
                self._record_diagnostic("rollback", status="failed", error=str(exc))
                raise
            self.rollback_verified = self._rules_loaded(0)
            if not self.rollback_verified:
                self._record_diagnostic(
                    "rollback", status="failed", error="empty ruleset was not confirmed loaded",
                )
            return self.rollback_verified
        except (IsolatedRuntimeError, OSError, TypeError) as exc:
            self._record_diagnostic("rollback", status="failed", error=str(exc))
            return False

    def verify_rollback(self, sid: int, rule_sha256: str) -> bool:
        return self._measure_bool(
            "post_rollback_verification", "runtime",
            lambda: self._verify_rollback_impl(sid, rule_sha256),
        )

    def _verify_rollback_impl(self, sid: int, rule_sha256: str) -> bool:
        if sid != self.sid or rule_sha256 != self.rule_sha256 or self.process is None:
            if self.probe_plan:
                self._record_not_run("rollback", "rollback runtime prerequisites failed")
            return False
        try:
            if self.process.poll() is not None:
                if self.probe_plan:
                    self._record_not_run("rollback", "isolated process is not running")
                return False
            rules_empty = self._rules_loaded(0)
            if self.probe_plan:
                if rules_empty:
                    no_sid = self._run_probe_plan("rollback", stop_on_failure=False)
                else:
                    self._record_not_run("rollback", "empty rollback ruleset was not verified")
                    no_sid = False
            elif rules_empty:
                no_sid = self._pcap_probe(self.attack_pcap, expect_alert=False)
                no_sid = self._pcap_probe(self.normal_pcap, expect_alert=False) and no_sid
                for path in self.negative_pcaps:
                    no_sid = self._pcap_probe(path, expect_alert=False) and no_sid
            else:
                no_sid = False
        except (IsolatedRuntimeError, OSError) as exc:
            self._record_diagnostic("rollback", status="failed", error=str(exc))
            if self.probe_plan:
                self._record_not_run("rollback", "rollback verification stopped after runtime error")
            no_sid = False
        finally:
            cleanup = self.shutdown()
            stopped = self.process is None or self.process.poll() is not None
            self.post_rollback_verified = bool(locals().get("no_sid", False) and cleanup and stopped)
        return self.post_rollback_verified

    def _record_not_run(self, phase: str, reason: str) -> None:
        completed = {
            (item.get("phase"), item.get("case")) for item in self.probe_results
        }
        for probe in self.probe_plan:
            if (phase, probe["case"]) in completed:
                continue
            self.probe_results.append({
                "case": probe["case"], "label": probe["label"],
                "scenario": probe.get("scenario"), "phase": phase,
                "pcap_sha256": probe["pcap_sha256"],
                "expected_alert": probe["expected_alert"] if phase == "active" else False,
                "candidate_alerts": 0, "result": False, "outcome": "NOT_RUN",
                "failure_reason": reason, "traffic_proof": False,
                "counter_baseline": None, "counter_delta": None,
                "replay_started_at": None, "replay_ended_at": None,
                "observation_started_at": None, "observation_ended_at": None,
                "eve_offset_start": None, "eve_offset_end": None,
                "elapsed_ms": None, "clock_type": "monotonic",
            })

    def _run_probe_plan(self, phase: str, *, stop_on_failure: bool) -> bool:
        all_passed = True
        for probe in self.probe_plan:
            passed = self._pcap_probe(
                Path(probe["path"]),
                expect_alert=probe["label"] == "ATTACK" if phase == "active" else False,
                case=probe["case"], label=probe["label"],
                scenario=probe.get("scenario"), phase=phase,
            )
            all_passed = passed and all_passed
            if not passed and stop_on_failure:
                self._record_not_run(phase, "stopped after failed active probe")
                break
            if self.deadline_monotonic is not None and time.monotonic() >= self.deadline_monotonic:
                self._record_not_run(phase, "lifecycle deadline reached")
                all_passed = False
                break
        return all_passed

    def shutdown(self) -> bool:
        """Only shut down the Popen-owned isolated process, never systemd."""
        shutdown_error = False
        try:
            if self.process is not None and self.process.poll() is None:
                self._command("shutdown")
                self.process.wait(timeout=20)
        except (IsolatedRuntimeError, subprocess.TimeoutExpired):
            shutdown_error = True
            self._record_diagnostic("cleanup", status="failed", error="graceful shutdown failed")
            if not self._terminate_child():
                self._record_diagnostic(
                    "cleanup", status="failed", error="child termination could not be verified",
                )
        finally:
            output = self._close_process_output()
            if output["stdout"] or output["stderr"]:
                self._record_diagnostic("cleanup", status="output", **output)
        process_stopped = self.process is None or self.process.poll() is not None
        acl_cleanup = True
        if process_stopped and getattr(self, "_acl_paths", None) is not None:
            try:
                remove_attempt_acls(
                    self._acl_paths, username=self.service_user,
                    transaction=getattr(self, "_acl_transaction", None),
                )
            except PrivilegeSeparationError as exc:
                acl_cleanup = False
                self._record_diagnostic("cleanup", status="failed", error=str(exc))
        if process_stopped and acl_cleanup:
            self.pidfile.unlink(missing_ok=True)
            self.socket_path.unlink(missing_ok=True)
            self.active_rules.unlink(missing_ok=True)
        artifacts_removed = not any(
            path.exists() for path in (self.pidfile, self.socket_path, self.active_rules)
        )
        cleanup_verified = not shutdown_error and process_stopped and acl_cleanup and artifacts_removed
        self._record_diagnostic(
            "cleanup", status="verified" if cleanup_verified else "failed",
            process_stopped=process_stopped, artifacts_removed=artifacts_removed,
        )
        return cleanup_verified
