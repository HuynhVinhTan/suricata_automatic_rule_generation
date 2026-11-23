"""Build the single bounded VM2 G2 generator invocation.

This module deliberately builds one SSH argv and one remote shell script.  It
does not retry, start capture, stop timers, or perform any live operation by
itself; callers must invoke :func:`run_generator_once` only after capture
readiness has been independently established.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
import shlex
import subprocess
from pathlib import PurePosixPath
from typing import Callable


VM2_TARGET = "kali@192.168.10.20"
GENERATOR_PATH = (
    "/home/kali/suricata-ai-showcase/releases/"
    "a8fe3e82e701beafc9e47fb7bc5b45064029f8be/scripts/lab_slow_port_scan.py"
)
EVIDENCE_ROOT = "/home/kali/suricata-ai-showcase/evidence/live"
TARGET_IP = "192.168.10.10"
SOURCE_IP = "192.168.10.20"
PORTS = tuple(range(18100, 18124))
PORTS_ARG = ",".join(str(port) for port in PORTS)
RUN_ID_RE = re.compile(r"^g2-live-attack-\d{8}T\d{6}Z-[0-9a-f]{16}$")
SSH_OPTIONS = (
    "-o", "BatchMode=yes",
    "-o", "StrictHostKeyChecking=yes",
    "-o", "ConnectTimeout=10",
    "-o", "ServerAliveInterval=10",
    "-o", "ServerAliveCountMax=2",
)


@dataclass(frozen=True)
class G2GeneratorRequest:
    """Validated inputs for one and only one G2 generator invocation."""

    run_id: str
    seed: int
    output_dir: str

    def __post_init__(self) -> None:
        if not RUN_ID_RE.fullmatch(self.run_id):
            raise ValueError("run_id must be a fresh g2-live-attack identifier")
        if not isinstance(self.seed, int) or isinstance(self.seed, bool) or self.seed < 0:
            raise ValueError("seed must be a non-negative integer")
        expected = PurePosixPath(EVIDENCE_ROOT) / self.run_id
        if PurePosixPath(self.output_dir) != expected:
            raise ValueError("output_dir must be the run-specific private evidence path")


def build_remote_generator_script(request: G2GeneratorRequest) -> str:
    """Build a safely quoted, single-shot remote shell script."""
    run_id = shlex.quote(request.run_id)
    output_dir = shlex.quote(request.output_dir)
    generator = shlex.quote(GENERATOR_PATH)
    ports = shlex.quote(PORTS_ARG)
    return "\n".join((
        "set -eu",
        "umask 077",
        f"run_id={run_id}",
        f"out_dir={output_dir}",
        'mkdir -p -- "$out_dir"',
        (
            f"exec /usr/bin/python3 {generator}"
            ' --run-id "$run_id"'
            f" --target {shlex.quote(TARGET_IP)}"
            f" --source-ip {shlex.quote(SOURCE_IP)}"
            f" --ports {ports}"
            " --interval 2.0"
            " --timeout 1.0"
            f" --seed {request.seed}"
            ' --out "$out_dir/generator.json"'
        ),
        "",
    ))


def build_ssh_argv(request: G2GeneratorRequest) -> list[str]:
    """Return one explicit SSH argv; the remote script is one final argument."""
    return ["ssh", *SSH_OPTIONS, VM2_TARGET, build_remote_generator_script(request)]


def run_generator_once(
    request: G2GeneratorRequest,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> subprocess.CompletedProcess[str]:
    """Run exactly once and propagate failure; there is intentionally no retry."""
    return runner(
        build_ssh_argv(request),
        check=True,
        timeout=180,
        text=True,
        capture_output=True,
    )


__all__ = [
    "EVIDENCE_ROOT",
    "G2GeneratorRequest",
    "GENERATOR_PATH",
    "PORTS",
    "PORTS_ARG",
    "TARGET_IP",
    "SOURCE_IP",
    "build_remote_generator_script",
    "build_ssh_argv",
    "run_generator_once",
]
