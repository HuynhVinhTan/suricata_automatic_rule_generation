"""VM1-only, loopback-only Suricata 8.0.3 isolated runtime adapter.

This adapter has no SSH or production service control. It owns exactly one
subprocess launched with --af-packet=lo, a unique UNIX socket and an isolated
-S exclusive rules file. It refuses to report ACTIVE without a real EVE SID
alert after tcpreplay on lo and refuses to report rollback without replaying
the same PCAP with zero candidate SID alerts.
"""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path

import yaml

from netids.lifecycle_ed25519 import sha256_file
from netids.trusted_replay import SID, RULE_SHA, _config_safe

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


def _run(argv: list[str], *, timeout: int = 60, deadline_monotonic=None) -> subprocess.CompletedProcess:
    if deadline_monotonic is not None:
        remaining = deadline_monotonic - time.monotonic()
        if remaining <= 0:
            raise IsolatedRuntimeError("Isolated runtime deadline exceeded")
        timeout = min(timeout, max(1, int(remaining)))
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
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
        self.attempt_id = self._validate_attempt_id(attempt_id)
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
        self.socket_path = self.attempt_root / "runtime" / "lab-suricata.socket"
        self.pidfile = self.attempt_root / "runtime" / "lab-suricata.pid"
        self.active_rules = self.attempt_root / "rules" / "active.rules"
        self.logdir = self.attempt_root / "logs"
        self.diagnostic_path = self.attempt_root / "logs" / "runtime-diagnostics.jsonl"
        self.process = None
        self._output_collectors = []
        self._old_rules = None
        self._activated = False
        self.activation_attempted = False
        self.rollback_attempted = False
        self.rollback_verified = False
        self.post_rollback_verified = False
        self.failure_phase = None
        self._last_attack_eve = ""
        self.probe_results = []
        self._preflight()

    @staticmethod
    def _validate_attempt_id(attempt_id: str | None) -> str | None:
        if attempt_id is None:
            return None
        if not isinstance(attempt_id, str) or not _ATTEMPT_ID.fullmatch(attempt_id):
            raise IsolatedRuntimeError("Invalid attempt-specific evidence identifier")
        return attempt_id

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
        for directory in (self.socket_path.parent, self.active_rules.parent, self.logdir):
            if directory.is_symlink():
                raise IsolatedRuntimeError("Symlink directory in isolated runtime")
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.active_rules.exists():
            raise IsolatedRuntimeError("Unexpected existing isolated ruleset; refuse overwrite")

    def _prepare_attempt_namespace(self) -> None:
        """Create one exclusive runtime evidence namespace without touching prior attempts."""
        if self.attempt_id is None:
            raise IsolatedRuntimeError("Attempt-specific evidence identifier is required")
        if not self.root.is_dir() or self.root.is_symlink():
            raise IsolatedRuntimeError("Exact isolated runtime root is missing/unsafe")
        if self.config_source.is_symlink() or not self.config_source.is_file():
            raise IsolatedRuntimeError("Isolated configuration template is missing or unsafe")
        _config_safe(self.config_source, self.root)
        try:
            configuration = yaml.safe_load(self.config_source.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, yaml.YAMLError) as exc:
            raise IsolatedRuntimeError("Invalid isolated Suricata configuration template") from exc
        if not isinstance(configuration, dict):
            raise IsolatedRuntimeError("Isolated Suricata configuration template is not an object")

        attempts = self.root / "attempts"
        if attempts.is_symlink():
            raise IsolatedRuntimeError("Attempt evidence directory is symlinked")
        attempts.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.attempt_root.exists() or self.attempt_root.is_symlink():
            raise IsolatedRuntimeError("Attempt evidence namespace already exists; refuse reuse")
        self.attempt_root.mkdir(mode=0o700)
        for directory in (self.socket_path.parent, self.active_rules.parent, self.logdir):
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)

        configuration["default-rule-path"] = str(self.active_rules.parent)
        configuration["rule-files"] = ["active.rules"]
        if configuration.get("unix-command") is not None and not isinstance(
            configuration.get("unix-command"), dict
        ):
            raise IsolatedRuntimeError("Isolated UNIX command configuration is invalid")
        unix_command = dict(configuration.get("unix-command") or {})
        unix_command["enabled"] = True
        unix_command["filename"] = str(self.socket_path)
        configuration["unix-command"] = unix_command
        try:
            _atomic(
                self.config,
                (yaml.safe_dump(configuration, sort_keys=False) + "\n").encode("utf-8"),
            )
        except (OSError, UnicodeError, TypeError, ValueError, yaml.YAMLError) as exc:
            raise IsolatedRuntimeError("Could not create effective attempt configuration") from exc

    def _validate_isolated_configuration(self) -> None:
        try:
            configuration = yaml.safe_load(self.config.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, yaml.YAMLError) as exc:
            raise IsolatedRuntimeError("Invalid isolated Suricata configuration") from exc
        if not isinstance(configuration, dict):
            raise IsolatedRuntimeError("Isolated Suricata configuration is not an object")

        unix_command = configuration.get("unix-command")
        if not isinstance(unix_command, dict) or unix_command.get("enabled") is not True:
            raise IsolatedRuntimeError("Isolated UNIX socket is not enabled in configuration")
        if Path(str(unix_command.get("filename", ""))).resolve() != self.socket_path.resolve():
            raise IsolatedRuntimeError("Isolated UNIX socket path is not attempt-specific")

        rule_files = configuration.get("rule-files")
        if not isinstance(rule_files, list) or len(rule_files) != 1 or not isinstance(rule_files[0], str):
            raise IsolatedRuntimeError("Isolated configuration must reference exactly one ruleset")
        default_rule_path = configuration.get("default-rule-path", ".")
        configured_rules = Path(rule_files[0])
        if not configured_rules.is_absolute():
            configured_rules = Path(default_rule_path) / configured_rules
        if configured_rules.resolve() != self.active_rules.resolve():
            raise IsolatedRuntimeError("Isolated configuration references a non-isolated ruleset")

        captures = configuration.get("af-packet", [])
        if not isinstance(captures, list) or not captures or any(
            not isinstance(entry, dict) or entry.get("interface") != "lo" for entry in captures
        ):
            raise IsolatedRuntimeError("Isolated configuration must capture loopback only")

    def _record_diagnostic(self, phase: str, **details) -> None:
        """Append bounded, redacted structured diagnostics; never mask the failure."""
        if details.get("status") == "failed":
            self.failure_phase = phase
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
        ]

    def _validation_rule_arguments(self, temporary: Path) -> list[str]:
        return [
            self.suricata, "-T", "--init-errors-fatal", "-c", str(self.config),
            "-S", str(temporary), "-l", str(self.logdir),
        ]

    def _command(self, command: str) -> object:
        self._check_deadline()
        try:
            result = _run([
                self.suricatasc, "-c", command, str(self.socket_path)
            ], timeout=75, deadline_monotonic=self.deadline_monotonic)
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
        _atomic(self.active_rules, self._old_rules)
        arguments = self._daemon_arguments()
        self._record_diagnostic("startup", status="started", arguments=arguments)
        try:
            self.process = subprocess.Popen(
                arguments, cwd=self.root, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
            )
            self._output_collectors = [
                _BoundedProcessOutput(getattr(self.process, "stdout", None)),
                _BoundedProcessOutput(getattr(self.process, "stderr", None)),
            ]
        except (OSError, ValueError) as exc:
            self._record_diagnostic("startup", status="failed", error=str(exc))
            raise IsolatedRuntimeError("Suricata startup initialization failed") from exc
        last_error = None
        for _ in range(40):
            self._check_deadline()
            if self.process.poll() is not None:
                output = self._close_process_output()
                self._record_diagnostic(
                    "startup", status="failed", exit_status=self.process.poll(), **output,
                )
                raise IsolatedRuntimeError("Suricata startup failed: daemon exited during initialization")
            if self.socket_path.exists():
                try:
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
            "socket", status="failed", error=str(last_error or "socket was not ready"), **output,
        )
        raise IsolatedRuntimeError(
            f"Isolated UNIX socket was not ready: {last_error or 'startup timeout'}"
        )

    def _pcap_probe(self, file: Path, *, expect_alert: bool, case=None, label=None, scenario=None, phase="active") -> bool:
        stage_name = f"probe_{phase}_{case or file.stem}"
        if self.latency_trace is None:
            return self._pcap_probe_impl(
                file, expect_alert=expect_alert, case=case, label=label,
                scenario=scenario, phase=phase,
            )
        with self.latency_trace.stage(stage_name, component="runtime"):
            return self._pcap_probe_impl(
                file, expect_alert=expect_alert, case=case, label=label,
                scenario=scenario, phase=phase,
            )

    def _pcap_probe_impl(self, file: Path, *, expect_alert: bool, case=None, label=None, scenario=None, phase="active") -> bool:
        self._check_deadline()
        eve = self.logdir / "eve.json"
        offset = eve.stat().st_size if eve.exists() else 0
        _run([
            self.tcpreplay, "--intf1=lo", "--pps=150", str(file),
        ], timeout=180, deadline_monotonic=self.deadline_monotonic)
        if self.deadline_monotonic is None:
            time.sleep(2)
        else:
            remaining = self.deadline_monotonic - time.monotonic()
            if remaining <= 0:
                raise IsolatedRuntimeError("Isolated runtime deadline exceeded")
            time.sleep(min(2, remaining))
        self._check_deadline()
        if not eve.is_file():
            return False
        with eve.open("rb") as reader:
            reader.seek(offset)
            events = reader.read().decode("utf-8").splitlines()
        found = 0
        for line in events:
            if not line.strip():
                continue
            try:
                data = json.loads(line)
            except ValueError:
                return False
            if (
                data.get("event_type") == "alert"
                and data.get("alert", {}).get("signature_id") == self.sid
            ):
                found += 1
        self.probe_results.append({
            "case": case,
            "label": label,
            "scenario": scenario,
            "phase": phase,
            "pcap_sha256": sha256_file(file),
            "expected_alert": expect_alert,
            "candidate_alerts": found,
            "events_seen": len([line for line in events if line.strip()]),
        })
        if not events:
            return False  # No new EVE events cannot prove the probe reached Suricata.
        if expect_alert:
            self._last_attack_eve = sha256_file(eve)
            return found > 0
        return found == 0

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
        directory = self.root / "runtime"
        temporary = directory / "validate-candidate.rules"
        if temporary.exists():
            return False
        try:
            _atomic(temporary, rule.encode("utf-8") + b"\n")
            result = _run(
                self._validation_rule_arguments(temporary),
                timeout=120, deadline_monotonic=self.deadline_monotonic,
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
            _atomic(self.active_rules, source.read_bytes())
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
            return False
        try:
            if not self._rules_loaded(1):
                return False
            if self.probe_plan:
                return all(
                    self._pcap_probe(
                        Path(probe["path"]),
                        expect_alert=probe["label"] == "ATTACK",
                        case=probe["case"], label=probe["label"],
                        scenario=probe.get("scenario"), phase="active",
                    )
                    for probe in self.probe_plan
                )
            return (
                self._pcap_probe(self.attack_pcap, expect_alert=True)
                and self._pcap_probe(self.normal_pcap, expect_alert=False)
                and all(
                    self._pcap_probe(path, expect_alert=False)
                    for path in self.negative_pcaps
                )
            )
        except (IsolatedRuntimeError, OSError):
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
            _atomic(self.active_rules, self._old_rules)
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
            return False
        try:
            if self.process.poll() is not None:
                return False
            if not self._rules_loaded(0):
                return False
            if self.probe_plan:
                no_sid = all(
                    self._pcap_probe(
                        Path(probe["path"]), expect_alert=False,
                        case=probe["case"], label=probe["label"],
                        scenario=probe.get("scenario"), phase="rollback",
                    )
                    for probe in self.probe_plan
                )
                cleanup = self.shutdown()
                self.post_rollback_verified = no_sid and cleanup and self.process.poll() is not None
                return self.post_rollback_verified
            no_sid = self._pcap_probe(self.attack_pcap, expect_alert=False)
            no_sid = no_sid and self._pcap_probe(self.normal_pcap, expect_alert=False)
            no_sid = no_sid and all(
                self._pcap_probe(path, expect_alert=False)
                for path in self.negative_pcaps
            )
            cleanup = self.shutdown()
            self.post_rollback_verified = no_sid and cleanup and self.process.poll() is not None
            return self.post_rollback_verified
        except (IsolatedRuntimeError, OSError) as exc:
            self._record_diagnostic("rollback", status="failed", error=str(exc))
            return False

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
            if self.process is not None and self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=10)
        finally:
            output = self._close_process_output()
            if output["stdout"] or output["stderr"]:
                self._record_diagnostic("cleanup", status="output", **output)
            self.pidfile.unlink(missing_ok=True)
            self.socket_path.unlink(missing_ok=True)
            self.active_rules.unlink(missing_ok=True)
        process_stopped = self.process is None or self.process.poll() is not None
        artifacts_removed = not any(
            path.exists() for path in (self.pidfile, self.socket_path, self.active_rules)
        )
        cleanup_verified = not shutdown_error and process_stopped and artifacts_removed
        self._record_diagnostic(
            "cleanup", status="verified" if cleanup_verified else "failed",
            process_stopped=process_stopped, artifacts_removed=artifacts_removed,
        )
        return cleanup_verified
