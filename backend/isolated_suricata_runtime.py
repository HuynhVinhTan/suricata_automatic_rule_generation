"""Strict isolated Suricata runtime adapter.

The adapter is intentionally inert until an authenticated lifecycle caller
supplies an exact candidate. It never targets the system service or production
rules directory.
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import tempfile
from pathlib import Path


class IsolatedRuntimeError(ValueError):
    pass


class IsolatedSuricataRuntime:
    def __init__(self, *, root: Path, config: Path, rules_dir: Path, logs_dir: Path,
                 pidfile: Path, socket_path: Path, interface: str = "lo",
                 suricata_bin: str = "suricata", suricatasc_bin: str = "suricatasc"):
        self.root = Path(root).resolve()
        self.config = Path(config).resolve()
        self.rules_dir = Path(rules_dir).resolve()
        self.logs_dir = Path(logs_dir).resolve()
        self.pidfile = Path(pidfile).resolve()
        self.socket_path = Path(socket_path).resolve()
        self.interface = interface
        self.suricata_bin = suricata_bin
        self.suricatasc_bin = suricatasc_bin
        if interface != "lo" or "isolated" not in self.root.name.lower():
            raise IsolatedRuntimeError("Runtime must be loopback-only and explicitly isolated")
        for path in (self.config, self.rules_dir, self.logs_dir, self.pidfile, self.socket_path):
            if not path.is_relative_to(self.root):
                raise IsolatedRuntimeError("Runtime path escapes isolated root")
        normalized_root = str(self.root).replace("\\", "/").lower()
        if any(marker in normalized_root for marker in ("/etc/suricata", "/var/lib/suricata", "/var/log/suricata", "/usr/share/suricata", "/usr/local/etc/suricata")):
            raise IsolatedRuntimeError("Production Suricata path is forbidden")

    def _rule_file(self, rule: str) -> Path:
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix=".syntax-", suffix=".rules", dir=self.rules_dir)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(rule + "\n")
        return Path(name)

    def validate(self, rule: str) -> bool:
        path = self._rule_file(rule)
        try:
            result = subprocess.run(
                [self.suricata_bin, "-T", "-c", str(self.config), "-S", str(path), "-l", str(self.logs_dir)],
                capture_output=True, text=True, check=False,
            )
            return result.returncode == 0
        finally:
            path.unlink(missing_ok=True)

    def activate(self, destination: Path, sid: int, rule_sha256: str) -> bool:
        destination = Path(destination).resolve()
        if not destination.is_relative_to(self.rules_dir) or not destination.is_file():
            return False
        if hashlib.sha256(destination.read_text(encoding="utf-8").strip().encode("utf-8")).hexdigest() != rule_sha256:
            return False
        command = [self.suricata_bin, "-D", "-c", str(self.config), "-S", str(destination),
                   "-i", self.interface, "--pidfile", str(self.pidfile), "--unix-socket", str(self.socket_path),
                   "-l", str(self.logs_dir)]
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        return result.returncode == 0

    def verify_active(self, sid: int, rule_sha256: str) -> bool:
        if not self.pidfile.is_file() or not self.socket_path.exists():
            return False
        try:
            pid = int(self.pidfile.read_text(encoding="ascii").strip())
            command_line = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode()
        except (OSError, ValueError, UnicodeError):
            return False
        return str(self.config) in command_line and f"{self.interface}" in command_line and self.rules_dir.as_posix() in command_line

    def rollback(self, destination: Path, sid: int, rule_sha256: str) -> bool:
        destination = Path(destination).resolve()
        if not destination.is_relative_to(self.rules_dir) or not destination.is_file():
            return False
        if hashlib.sha256(destination.read_text(encoding="utf-8").strip().encode("utf-8")).hexdigest() != rule_sha256:
            return False
        result = subprocess.run(
            [self.suricatasc_bin, "-s", str(self.socket_path), "-c", "shutdown"],
            capture_output=True, text=True, check=False,
        )
        return result.returncode == 0

    def verify_rollback(self, sid: int, rule_sha256: str) -> bool:
        return not self.socket_path.exists() and not self.pidfile.exists()
