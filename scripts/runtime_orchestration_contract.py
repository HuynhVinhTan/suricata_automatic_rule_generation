"""Offline contracts for the owner-controlled G1/G2/G3/G4/G6 runbook.

This module only builds and validates command data. It never contacts a VM,
starts a service, creates a key, captures traffic, or runs a worker.
"""

from __future__ import annotations

from datetime import datetime
import hashlib
import json
from pathlib import PurePosixPath
import re


CAPTURE_SERVICE = "suricata-ai-capture.service"
CAPTURE_INTERFACE = "ens33"
CAPTURE_SNAPLEN = 262144
CAPTURE_DURATION_SECONDS = 60
CAPTURE_BPF_FILTER = (
    "tcp and host 192.168.10.20 and host 192.168.10.10 "
    "and (port 18080 or portrange 18100-18123)"
)
READINESS_TIMEOUT_SECONDS = 10
CAPTURE_ROOT = PurePosixPath("/var/lib/suricata-ai-capture")
VM1_OUTBOX = PurePosixPath("/home/tanhv/suricata-ai-outbox")
VM1_IP = "192.168.10.10"
VM2_IP = "192.168.10.20"
CAPTURE_ID = re.compile(r"^capture-\d{8}T\d{6}Z-[0-9a-f]{16}$")
GENERATOR_ID = re.compile(r"^g[24]-(?:live-)?[a-z]+-\d{8}T\d{6}Z-[0-9a-f]{16}$")
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


def validate_capture_generator_evidence(
    *,
    scenario: str,
    capture_id: str,
    generator_id: str,
    pcap_bytes: bytes,
    native_manifest_bytes: bytes,
    native_manifest: dict,
    ready_marker: dict,
    generator_bytes: bytes,
) -> dict[str, str | int]:
    """Validate one G4 session from bytes, hashes, tuples, counts, and time."""
    correlate_capture_and_generator(capture_id, generator_id)
    if scenario not in {"ATTACK", "NORMAL"}:
        raise ValueError("unsupported scenario")
    try:
        generator = json.loads(generator_bytes.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("generator evidence is not valid JSON") from exc
    if not isinstance(generator, dict):
        raise ValueError("generator evidence must be an object")
    pcap_sha256 = hashlib.sha256(pcap_bytes).hexdigest()
    native_sha256 = hashlib.sha256(native_manifest_bytes).hexdigest()
    generator_sha256 = hashlib.sha256(generator_bytes).hexdigest()
    if native_manifest.get("run_id") != capture_id or ready_marker.get("run_id") != capture_id:
        raise ValueError("capture ID mismatch")
    if native_manifest.get("pcap_sha256") != pcap_sha256 or ready_marker.get("pcap_sha256") != pcap_sha256:
        raise ValueError("PCAP digest mismatch")
    if ready_marker.get("manifest_sha256") != native_sha256:
        raise ValueError("native manifest digest mismatch")
    if generator.get("run_id") != generator_id:
        raise ValueError("generator ID mismatch")
    if generator.get("scenario") != scenario:
        raise ValueError("scenario mismatch")
    if generator.get("source_ip") != VM2_IP or generator.get("target_ip") != VM1_IP:
        raise ValueError("generator identity mismatch")
    metadata = native_manifest.get("capture_metadata")
    attempts = generator.get("attempts")
    if not isinstance(metadata, dict) or not isinstance(attempts, list):
        raise ValueError("capture or generator counts are missing")
    if metadata.get("interface") != CAPTURE_INTERFACE or metadata.get("bpf_filter") != CAPTURE_BPF_FILTER:
        raise ValueError("capture interface or BPF filter mismatch")
    if (
        metadata.get("packet_records_complete") is not True
        or metadata.get("snaplen_truncated") is not False
        or metadata.get("capture_drops") is not False
    ):
        raise ValueError("capture integrity is not verified")
    if native_manifest.get("source_ipv4") != VM2_IP or native_manifest.get("destination_ipv4") != VM1_IP:
        raise ValueError("native capture identity mismatch")
    if not isinstance(metadata.get("packets"), int) or metadata["packets"] < len(attempts):
        raise ValueError("native packet count mismatch")
    if metadata.get("initial_syn") != len(attempts) or generator.get("attempt_count") != len(attempts):
        raise ValueError("capture/generator count mismatch")
    try:
        sealed = datetime.fromisoformat(str(metadata["sealed_at"]).replace("Z", "+00:00"))
        started = datetime.fromisoformat(str(generator["started_at_utc"]).replace("Z", "+00:00"))
        ended = datetime.fromisoformat(str(generator["ended_at_utc"]).replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("invalid evidence timestamp") from exc
    if sealed.tzinfo is None or started.tzinfo is None or ended.tzinfo is None:
        raise ValueError("evidence timestamps must include timezone")
    if not started <= ended <= sealed:
        raise ValueError("capture/generator timestamp order mismatch")
    for attempt in attempts:
        if not isinstance(attempt, dict):
            raise ValueError("malformed generator tuple")
        if (
            attempt.get("source_ip") != VM2_IP
            or attempt.get("destination_ip") != VM1_IP
            or not isinstance(attempt.get("source_port"), int)
            or not isinstance(attempt.get("destination_port"), int)
        ):
            raise ValueError("generator tuple identity mismatch")
    ports = {attempt["destination_port"] for attempt in attempts}
    if scenario == "ATTACK" and ports != set(G4_PORTS):
        raise ValueError("Attack destination-port set mismatch")
    if scenario == "NORMAL":
        open_attempts = [attempt for attempt in attempts if attempt.get("destination_port") == G4_NORMAL_OPEN_PORT]
        closed_attempts = [attempt for attempt in attempts if attempt.get("destination_port") in G4_NORMAL_CLOSED_PORTS]
        if len(open_attempts) != 22 or len(closed_attempts) != 2:
            raise ValueError("Normal port/count profile mismatch")
    return {
        "capture_id": capture_id,
        "generator_id": generator_id,
        "pcap_sha256": pcap_sha256,
        "native_manifest_sha256": native_sha256,
        "generator_sha256": generator_sha256,
        "attempt_count": len(attempts),
    }


def build_vm1_capture_readiness_script() -> str:
    """Build the non-blocking start/readiness gate used before a generator."""
    return "\n".join((
        "set -eu",
        "start_epoch=$(date +%s)",
        f"startup_deadline=$((start_epoch+{READINESS_TIMEOUT_SECONDS}))",
        f"capture_deadline=$((start_epoch+{CAPTURE_DURATION_SECONDS}))",
        f"sudo systemctl start --no-block {CAPTURE_SERVICE}",
        "while :; do",
        f"  state=$(systemctl show -p ActiveState --value {CAPTURE_SERVICE})",
        f"  substate=$(systemctl show -p SubState --value {CAPTURE_SERVICE})",
        "  now=$(date +%s)",
        "  if [ \"$now\" -ge \"$capture_deadline\" ]; then",
        "    systemctl status --no-pager --full " + CAPTURE_SERVICE + " >&2 || true",
        "    exit 75",
        "  fi",
        "  if [ \"$state\" != activating ] || [ \"$substate\" != start ]; then",
        "    systemctl status --no-pager --full " + CAPTURE_SERVICE + " >&2 || true",
        "    exit 75",
        "  fi",
        f"  if pgrep -af '[/]tcpdump[[:space:]]+-i[[:space:]]+{CAPTURE_INTERFACE}[[:space:]]+-s[[:space:]]+{CAPTURE_SNAPLEN}[[:space:]]+-n[[:space:]]+-U[[:space:]]+-w[[:space:]]+' >/dev/null; then",
        "    printf '%s\\n' G2_CAPTURE_READY=TRUE",
        "    exit 0",
        "  fi",
        "  if [ \"$now\" -ge \"$startup_deadline\" ]; then",
        "    systemctl status --no-pager --full " + CAPTURE_SERVICE + " >&2 || true",
        "    exit 75",
        "  fi",
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


def g3_release_paths(*, host_root: PurePosixPath, release_sha: str) -> dict[str, str]:
    """Return versioned G3 paths; no current-pointer replacement is allowed."""
    if not re.fullmatch(r"[0-9a-f]{40}", release_sha):
        raise ValueError("release_sha must be a full Git commit SHA")
    release = PurePosixPath(host_root) / "releases" / release_sha
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


def g4_release_paths(
    *,
    vm1_release_sha: str,
    vm2_release_sha: str,
    vm3_release_sha: str,
) -> dict[str, str]:
    """Return the exact versioned roots used by the prepared G4 controller."""
    commits = {
        "vm1_release_sha": vm1_release_sha,
        "vm2_release_sha": vm2_release_sha,
        "vm3_release_sha": vm3_release_sha,
    }
    for name, value in commits.items():
        if not re.fullmatch(r"[0-9a-f]{40}", value):
            raise ValueError(f"{name} must be a full lowercase Git commit SHA")
    return {
        "vm1_release": str(PurePosixPath("/home/tanhv/suricata-ai-showcase/releases") / vm1_release_sha),
        "vm2_generator": str(
            PurePosixPath("/home/kali/suricata-ai-showcase/releases")
            / vm2_release_sha / "scripts/lab_slow_port_scan.py"
        ),
        "vm3_release": str(PurePosixPath("/home/tanhv/suricata-ai-showcase/releases") / vm3_release_sha),
    }
