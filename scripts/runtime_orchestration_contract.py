"""Offline contracts for the owner-controlled G1/G2/G3/G4/G6 runbook.

This module only builds and validates command data. It never contacts a VM,
starts a service, creates a key, captures traffic, or runs a worker.
"""

from __future__ import annotations

from pathlib import PurePosixPath
import re


CAPTURE_SERVICE = "suricata-ai-capture.service"
CAPTURE_INTERFACE = "ens33"
CAPTURE_SNAPLEN = 262144
CAPTURE_ROOT = PurePosixPath("/var/lib/suricata-ai-capture")
VM1_OUTBOX = PurePosixPath("/home/tanhv/suricata-ai-outbox")
VM1_IP = "192.168.10.10"
VM2_IP = "192.168.10.20"
CAPTURE_ID = re.compile(r"^capture-\d{8}T\d{6}Z-[0-9a-f]{16}$")
GENERATOR_ID = re.compile(r"^g[24]-(?:live-)?[a-z]+-\d{8}T\d{6}Z-[0-9a-f]{16}$")
RELEASE_SHA = "d1005c24f94c3d994a9fff7cdb780c4ca90b3daa"
G4_PORTS = tuple(range(18100, 18124))
G4_NORMAL_CLOSED_PORTS = (18100, 18101)
G4_NORMAL_OPEN_PORT = 18080


def capture_bundle_paths(capture_id: str, *, outbox: PurePosixPath = VM1_OUTBOX) -> tuple[str, str, str]:
    """Return the actual sealed outbox filenames, never generic names."""
    if not CAPTURE_ID.fullmatch(capture_id):
        raise ValueError("capture_id is not a backend.pcap_capture ID")
    root = PurePosixPath(outbox) / capture_id
    return tuple(str(root / f"{capture_id}{suffix}") for suffix in (
        ".pcap", ".manifest.json", ".ready.json",
    ))


def worker_bundle_paths(capture_id: str, *, input_root: PurePosixPath) -> tuple[str, str, str]:
    """Return the flat filenames produced by pcap_handoff.send on VM3."""
    if not CAPTURE_ID.fullmatch(capture_id):
        raise ValueError("capture_id is not a backend.pcap_capture ID")
    root = PurePosixPath(input_root)
    return tuple(str(root / f"{capture_id}{suffix}") for suffix in (
        ".pcap", ".manifest.json", ".ready.json",
    ))


def correlate_capture_and_generator(capture_id: str, generator_id: str) -> dict[str, str]:
    """Bind independent IDs without renaming either evidence set."""
    if not CAPTURE_ID.fullmatch(capture_id):
        raise ValueError("invalid capture_id")
    if not GENERATOR_ID.fullmatch(generator_id):
        raise ValueError("invalid generator_id")
    if capture_id == generator_id:
        raise ValueError("capture and generator IDs must remain distinct")
    return {"capture_id": capture_id, "generator_id": generator_id}


def build_vm1_capture_readiness_script() -> str:
    """Build the non-blocking start/readiness gate used before a generator."""
    return "\n".join((
        "set -eu",
        f"sudo systemctl start --no-block {CAPTURE_SERVICE}",
        "deadline=$(($(date +%s)+10))",
        "while :; do",
        f"  state=$(systemctl show -p ActiveState --value {CAPTURE_SERVICE})",
        f"  substate=$(systemctl show -p SubState --value {CAPTURE_SERVICE})",
        f"  if [ \"$state\" = activating ] && [ \"$substate\" = running ] && \\",
        f"     pgrep -af '[t]cpdump -i {CAPTURE_INTERFACE} -s {CAPTURE_SNAPLEN}' >/dev/null; then",
        "    printf '%s\\n' G2_CAPTURE_READY=TRUE",
        "    exit 0",
        "  fi",
        "  if [ \"$state\" = active ] || [ \"$state\" = failed ] || [ \"$state\" = inactive ]; then",
        "    systemctl status --no-pager --full " + CAPTURE_SERVICE + " >&2 || true",
        "    exit 75",
        "  fi",
        "  [ \"$(date +%s)\" -lt \"$deadline\" ] || exit 75",
        "  sleep 0.2",
        "done",
        "",
    ))


def build_worker_argv(
    capture_id: str,
    *,
    input_root: PurePosixPath,
    private_root: PurePosixPath,
    python: str = "/home/tanhv/suricata-ai-venv/bin/python",
) -> list[str]:
    """Build the exact VM3 worker argv for one verified sealed bundle."""
    pcap, manifest, _ready = worker_bundle_paths(capture_id, input_root=input_root)
    return [
        python, "-m", "backend.worker",
        "--pcap", pcap,
        "--input-root", str(input_root),
        "--src", VM2_IP,
        "--dst", VM1_IP,
        "--private-root", str(private_root),
        "--run-id", capture_id,
        "--manifest", manifest,
    ]


def g3_release_paths(*, host_root: PurePosixPath) -> dict[str, str]:
    """Return versioned G3 paths; no current-pointer replacement is allowed."""
    release = PurePosixPath(host_root) / "releases" / RELEASE_SHA
    return {
        "release": str(release),
        "private_key": str(PurePosixPath(host_root) / "private/g3/g3-signer.pem"),
        "public_key": str(PurePosixPath(host_root) / "private/g3/g3-signer.pub.pem"),
        "fingerprint": str(PurePosixPath(host_root) / "private/g3/g3-signer.pub.sha256"),
        "ledger": str(PurePosixPath(host_root) / "private/g3/g3-replay.sqlite3"),
        "record": str(PurePosixPath(host_root) / "evidence/g3/record.json"),
        "envelope": str(PurePosixPath(host_root) / "evidence/g3/envelope.json"),
        "verification": str(PurePosixPath(host_root) / "evidence/g3/verification.json"),
    }
