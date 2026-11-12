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
import time
from pathlib import Path

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


def _run(argv: list[str], *, timeout: int = 60) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise IsolatedRuntimeError("Isolated command failed or timed out") from exc
    if result.returncode:
        raise IsolatedRuntimeError("Isolated command returned a nonzero status")
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
        root: Path = ROOT,
    ):
        self.root = Path(root)
        self.sid = candidate_sid
        self.rule_sha256 = candidate_rule_sha256
        self.config = Path(config)
        self.attack_pcap = Path(attack_pcap)
        self.normal_pcap = Path(normal_pcap)
        self.attack_sha256 = attack_sha256
        self.normal_sha256 = normal_sha256
        self.suricata = str(suricata)
        self.suricatasc = str(suricatasc)
        self.tcpreplay = str(tcpreplay)
        self.socket_path = self.root / "runtime" / "lab-suricata.socket"
        self.pidfile = self.root / "runtime" / "lab-suricata.pid"
        self.active_rules = self.root / "rules" / "active.rules"
        self.logdir = self.root / "logs"
        self.process = None
        self._old_rules = None
        self._activated = False
        self._last_attack_eve = ""
        self._preflight()

    def _preflight(self) -> None:
        if not is_verified_vm1_host():
            raise IsolatedRuntimeError("Wrong host or ens33 address; isolated VM1 only")
        if not self.root.is_dir() or self.root.is_symlink():
            raise IsolatedRuntimeError("Exact isolated runtime root is missing/unsafe")
        if not Path("/sys/class/net/lo").exists():
            raise IsolatedRuntimeError("Loopback interface is unavailable")
        _config_safe(self.config, self.root)
        for file, expected in (
            (self.attack_pcap, self.attack_sha256),
            (self.normal_pcap, self.normal_sha256),
        ):
            if file.is_symlink() or not file.is_file() or sha256_file(file) != expected:
                raise IsolatedRuntimeError("Pinned replay PCAP is missing or changed")
        for executable in (self.suricata, self.suricatasc, self.tcpreplay):
            if not Path(executable).is_file():
                raise IsolatedRuntimeError("Required preinstalled tool not available")
        version = _run([self.suricata, "-V"], timeout=20).stdout
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

    def _command(self, command: str) -> object:
        result = _run([
            self.suricatasc, "-c", command, str(self.socket_path)
        ], timeout=75)
        try:
            output = json.loads(result.stdout)
        except ValueError as exc:
            raise IsolatedRuntimeError("Suricata socket returned invalid JSON") from exc
        if not isinstance(output, dict) or output.get("return") != "OK":
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
        if self.process is not None:
            raise IsolatedRuntimeError("Isolated daemon already owned")
        self._old_rules = b"# no active candidate rules in this isolated test\n"
        _atomic(self.active_rules, self._old_rules)
        arguments = [
            self.suricata, "-c", str(self.config), "-S", str(self.active_rules),
            "-l", str(self.logdir), "--af-packet=lo",
            "--pidfile", str(self.pidfile), f"--unix-socket={self.socket_path}",
            "--init-errors-fatal", "-k", "none",
        ]
        self.process = subprocess.Popen(
            arguments, cwd=self.root, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
        )
        for _ in range(40):
            if self.process.poll() is not None:
                raise IsolatedRuntimeError("Isolated Suricata exited during startup")
            if self.socket_path.exists():
                try:
                    version = self._command("version")
                    if "8.0.3" in str(version):
                        mode = self._command("capture-mode")
                        if "AF_PACKET" not in str(mode):
                            raise IsolatedRuntimeError("Wrong isolated capture mode")
                        if not self._rules_loaded(0):
                            raise IsolatedRuntimeError("Isolated baseline is not an empty ruleset")
                        return
                except IsolatedRuntimeError:
                    pass
            time.sleep(0.25)
        raise IsolatedRuntimeError("Isolated UNIX socket was not ready")

    def _pcap_probe(self, file: Path, *, expect_alert: bool) -> bool:
        eve = self.logdir / "eve.json"
        offset = eve.stat().st_size if eve.exists() else 0
        _run([
            self.tcpreplay, "--intf1=lo", "--pps=150", str(file),
        ], timeout=180)
        time.sleep(2)
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
        if not events:
            return False  # No new EVE events cannot prove the probe reached Suricata.
        if expect_alert:
            self._last_attack_eve = sha256_file(eve)
            return found > 0
        return found == 0

    def validate(self, rule: str) -> bool:
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
            result = _run([
                self.suricata, "-T", "--init-errors-fatal",
                "-c", str(self.config), "-S", str(temporary),
                "-l", str(self.logdir),
            ], timeout=120)
            return result.returncode == 0
        except IsolatedRuntimeError:
            return False
        finally:
            temporary.unlink(missing_ok=True)

    def activate(self, destination: Path, sid: int, rule_sha256: str) -> bool:
        if sid != self.sid or rule_sha256 != self.rule_sha256:
            return False
        source = Path(destination)
        if source.is_symlink() or sha256_file(source) != rule_sha256:
            return False
        try:
            self._start()
            _atomic(self.active_rules, source.read_bytes())
            self._command("ruleset-reload-rules")
            if not self._rules_loaded(1):
                raise IsolatedRuntimeError("Exact candidate rule not confirmed loaded")
            self._activated = True
            return True
        except (IsolatedRuntimeError, OSError):
            return False

    def verify_active(self, sid: int, rule_sha256: str) -> bool:
        if (
            sid != self.sid or rule_sha256 != self.rule_sha256 or not self._activated
            or self.process is None or self.process.poll() is not None
            or sha256_file(self.active_rules) != self.rule_sha256
        ):
            return False
        try:
            if not self._rules_loaded(1):
                return False
            return (
                self._pcap_probe(self.attack_pcap, expect_alert=True)
                and self._pcap_probe(self.normal_pcap, expect_alert=False)
            )
        except (IsolatedRuntimeError, OSError):
            return False

    def rollback(self, destination: Path, sid: int, rule_sha256: str) -> bool:
        if sid != self.sid or rule_sha256 != self.rule_sha256 or self.process is None:
            return False
        try:
            _atomic(self.active_rules, self._old_rules)
            self._command("ruleset-reload-rules")
            return self._rules_loaded(0)
        except (IsolatedRuntimeError, OSError, TypeError):
            return False

    def verify_rollback(self, sid: int, rule_sha256: str) -> bool:
        if sid != self.sid or rule_sha256 != self.rule_sha256 or self.process is None:
            return False
        try:
            if self.process.poll() is not None:
                return False
            if not self._rules_loaded(0):
                return False
            no_sid = self._pcap_probe(self.attack_pcap, expect_alert=False)
            self.shutdown()
            return no_sid and self.process.poll() is not None
        except (IsolatedRuntimeError, OSError):
            return False

    def shutdown(self) -> None:
        """Only shut down the Popen-owned isolated process, never systemd."""
        if self.process is None:
            return
        try:
            if self.process.poll() is None:
                self._command("shutdown")
                self.process.wait(timeout=20)
        except (IsolatedRuntimeError, subprocess.TimeoutExpired):
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=10)
        finally:
            self.pidfile.unlink(missing_ok=True)
            self.socket_path.unlink(missing_ok=True)
            self.active_rules.unlink(missing_ok=True)
