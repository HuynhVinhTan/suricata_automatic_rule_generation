"""Bounded, opt-in VM1 PCAP capture and sealing helper."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from backend import pcap_handoff


CAPTURE_ROOT = Path("/var/lib/suricata-ai-capture")
OUTBOX = Path("/home/tanhv/suricata-ai-outbox")
TCPDUMP = "/usr/bin/tcpdump"
INTERFACE = "ens33"
BPF_FILTER = "tcp and src host 192.168.10.20 and dst host 192.168.10.10"
SOURCE_IP = "192.168.10.20"
DESTINATION_IP = "192.168.10.10"
SNAPLEN = 262144
DEFAULT_DURATION_SECONDS = 60
MAX_DURATION_SECONDS = 60
MAX_PCAP_BYTES = 64 * 1024 * 1024
MIN_FREE_BYTES = 3 * 1024**3
MAX_RETAINED_RUNS = 16
MAX_RETAINED_BYTES = 1024**3
STOP_GRACE_SECONDS = 5
LINUX_CAPTURE = sys.platform.startswith("linux")
RUN_ID = re.compile(r"^capture-\d{8}T\d{6}Z-[0-9a-f]{16}$")


class CaptureError(ValueError):
    """A capture safety or configuration invariant is not met."""


def _new_run_id() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"capture-{timestamp}-{secrets.token_hex(8)}"


def _directory(path: Path) -> Path:
    path = Path(path)
    if not path.is_absolute():
        raise CaptureError("Capture and outbox roots must be absolute paths")
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise CaptureError("Symlink paths are not allowed for capture roots")
    if path.is_symlink() or not path.is_dir():
        raise CaptureError("Capture and outbox roots must be existing directories")
    resolved = path.resolve(strict=True)
    if resolved == resolved.parent:
        raise CaptureError("Filesystem root is not an acceptable directory")
    if os.name == "posix":
        info = resolved.stat()
        if info.st_mode & 0o077:
            raise CaptureError("Capture and outbox directories must have mode 0700")
        if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
            raise CaptureError("Capture and outbox directories must be owned by the service user")
    return resolved


def _size_limit_preexec(limit: int):
    import resource

    def apply_limit() -> None:
        resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))

    return apply_limit


def _tree_size(root: Path) -> int:
    size = 0
    for path in root.rglob("*"):
        if path.is_symlink():
            raise CaptureError("Symlinks are not allowed in retained capture data")
        if path.is_file():
            size += path.stat().st_size
        elif not path.is_dir():
            raise CaptureError("Unsupported file type in retained capture data")
    return size


def _capture_entries(root: Path, *, strict: bool) -> dict[str, Path]:
    entries = {}
    for path in root.iterdir():
        if strict and path.name == ".capture.lock":
            if path.is_symlink() or not path.is_file():
                raise CaptureError("Capture lock must be a regular file")
            continue
        if not RUN_ID.fullmatch(path.name):
            if strict:
                raise CaptureError("Unexpected entry in private capture root")
            continue
        if path.is_symlink() or not path.is_dir():
            raise CaptureError("Retained capture runs must be regular directories")
        entries[path.name] = path
    return entries


def _retained_usage(capture_root: Path, outbox: Path) -> tuple[int, int]:
    captures = _capture_entries(capture_root, strict=True)
    bundles = _capture_entries(outbox, strict=False)
    run_ids = captures.keys() | bundles.keys()
    size = sum(_tree_size(folder) for folder in captures.values())
    size += sum(_tree_size(folder) for folder in bundles.values())
    return len(run_ids), size


def _write_status(run_dir: Path, data: dict) -> None:
    target = run_dir / "status.json"
    with target.open("x", encoding="utf-8") as stream:
        json.dump(data, stream, sort_keys=True, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    if os.name == "posix":
        target.chmod(0o600)


def _status(run_id: str, state: str, diagnostic: str, **details) -> dict:
    return {
        "run_id": run_id,
        "status": state,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "diagnostic": diagnostic[:200],
        **details,
    }


def _stop(process: subprocess.Popen, *, grace: int) -> int:
    try:
        process.send_signal(signal.SIGINT)
    except ProcessLookupError:
        pass
    try:
        return process.wait(timeout=grace)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        try:
            process.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            pass
        raise CaptureError("tcpdump did not stop within the shutdown grace period") from exc


def _start_capture(pcap_path: Path, duration_seconds: int) -> int:
    process = subprocess.Popen(
        [
            TCPDUMP, "-i", INTERFACE, "-s", str(SNAPLEN), "-n", "-U",
            "-w", str(pcap_path), BPF_FILTER,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        shell=False,
        preexec_fn=_size_limit_preexec(MAX_PCAP_BYTES),
    )
    try:
        try:
            return process.wait(timeout=duration_seconds)
        except subprocess.TimeoutExpired:
            return _stop(process, grace=STOP_GRACE_SECONDS)
    except KeyboardInterrupt:
        _stop(process, grace=STOP_GRACE_SECONDS)
        raise


def _capture_unlocked(
    *, capture_root: Path, outbox: Path,
    duration_seconds: int = DEFAULT_DURATION_SECONDS,
) -> dict:
    if not LINUX_CAPTURE:
        raise CaptureError("Live capture is supported only on Linux")
    if type(duration_seconds) is not int or not 1 <= duration_seconds <= MAX_DURATION_SECONDS:
        raise CaptureError("Capture duration must be from 1 through 60 seconds")
    capture_dir = _directory(capture_root)
    outbox_dir = _directory(outbox)
    if capture_dir == outbox_dir or capture_dir in outbox_dir.parents or outbox_dir in capture_dir.parents:
        raise CaptureError("Private capture root and sender outbox must be separate")
    free_space = min(
        shutil.disk_usage(capture_dir).free,
        shutil.disk_usage(outbox_dir).free,
    )
    if free_space < MIN_FREE_BYTES:
        raise CaptureError("At least 3 GiB must be free on both capture and outbox storage")
    retained_runs, retained_bytes = _retained_usage(capture_dir, outbox_dir)
    if (
        retained_runs >= MAX_RETAINED_RUNS
        or retained_bytes + 2 * MAX_PCAP_BYTES + 8192 > MAX_RETAINED_BYTES
    ):
        raise CaptureError("Capture retention limit reached; operator review and cleanup required")

    run_dir = None
    run_id = ""
    for _attempt in range(5):
        run_id = _new_run_id()
        if not RUN_ID.fullmatch(run_id):
            raise CaptureError("Generated run ID is invalid")
        if (capture_dir / run_id).exists() or (capture_dir / run_id).is_symlink():
            continue
        if (outbox_dir / run_id).exists() or (outbox_dir / run_id).is_symlink():
            continue
        try:
            run_dir = capture_dir / run_id
            run_dir.mkdir(mode=0o700, exist_ok=False)
            break
        except FileExistsError:
            run_dir = None
    if run_dir is None:
        raise CaptureError("Could not allocate a unique run ID without overwriting evidence")

    pcap_path = run_dir / "capture.pcap"
    try:
        try:
            return_code = _start_capture(pcap_path, duration_seconds)
        except KeyboardInterrupt:
            _write_status(run_dir, _status(run_id, "interrupted", "Capture interrupted; partial evidence retained"))
            return {"status": "interrupted", "run_id": run_id}
        except (OSError, CaptureError) as exc:
            message = "tcpdump could not start or stop cleanly" if isinstance(exc, OSError) else str(exc)
            _write_status(run_dir, _status(run_id, "failed", message, error_type=type(exc).__name__))
            return {"status": "failed", "run_id": run_id, "diagnostic": message}
        if return_code != 0:
            message = "tcpdump exited unsuccessfully; partial evidence retained"
            _write_status(run_dir, _status(run_id, "failed", message, return_code=return_code))
            return {"status": "failed", "run_id": run_id, "diagnostic": message}
        if pcap_path.is_symlink() or not pcap_path.is_file():
            raise CaptureError("tcpdump did not create a regular PCAP file")
        with pcap_path.open("rb+") as stream:
            stream.flush()
            os.fsync(stream.fileno())
        if pcap_path.stat().st_size > MAX_PCAP_BYTES:
            raise CaptureError("Captured PCAP exceeds the hard maximum file size")
        digest = hashlib.sha256()
        with pcap_path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        sha256 = digest.hexdigest()
        try:
            audit = pcap_handoff.audit_pcap(pcap_path, SOURCE_IP, DESTINATION_IP)
        except pcap_handoff.HandoffError as exc:
            if "no packets or expected initial SYN" in str(exc):
                message = "No packets or initial SYN; capture is preserved and not processed"
                _write_status(run_dir, _status(run_id, "non_processed", message, pcap_sha256=sha256))
                return {"status": "non_processed", "run_id": run_id, "diagnostic": message}
            raise
        result = pcap_handoff.bundle(
            pcap=pcap_path,
            input_root=run_dir,
            outbox=outbox_dir,
            run_id=run_id,
            src=SOURCE_IP,
            dst=DESTINATION_IP,
            expected_sha256=sha256,
            expected_syn=audit["initial_syn"],
            capture_kind="raw",
        )
        summary = {key: value for key, value in result.items() if key not in {"status", "run_id"}}
        _write_status(
            run_dir,
            _status(run_id, "sealed", "Raw capture audited and sealed", **summary),
        )
        return result
    except (OSError, pcap_handoff.HandoffError, CaptureError) as exc:
        message = str(exc)[:200]
        if not (run_dir / "status.json").exists():
            _write_status(
                run_dir,
                _status(run_id, "failed", message, error_type=type(exc).__name__),
            )
        return {"status": "failed", "run_id": run_id, "diagnostic": message}


def capture_once(
    *, capture_root: Path, outbox: Path,
    duration_seconds: int = DEFAULT_DURATION_SECONDS,
) -> dict:
    if not LINUX_CAPTURE:
        raise CaptureError("Live capture is supported only on Linux")
    if type(duration_seconds) is not int or not 1 <= duration_seconds <= MAX_DURATION_SECONDS:
        raise CaptureError("Capture duration must be from 1 through 60 seconds")
    root = _directory(capture_root)
    lock = root / ".capture.lock"
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(lock, flags, 0o600)
    except FileExistsError as exc:
        raise CaptureError("Capture lock exists; another or interrupted run needs operator review") from exc
    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
            stream.write(f"pid={os.getpid()}\n")
            stream.flush()
            os.fsync(stream.fileno())
        return _capture_unlocked(
            capture_root=root,
            outbox=outbox,
            duration_seconds=duration_seconds,
        )
    finally:
        lock.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--duration-seconds", type=int, default=DEFAULT_DURATION_SECONDS,
        help="bounded capture duration (1-60 seconds; default: 60)",
    )
    args = parser.parse_args(argv)
    try:
        result = capture_once(
            capture_root=CAPTURE_ROOT,
            outbox=OUTBOX,
            duration_seconds=args.duration_seconds,
        )
    except Exception as exc:
        result = {
            "status": "failed",
            "error_type": type(exc).__name__,
            "diagnostic": str(exc)[:200],
        }
        print(json.dumps(result, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] in {"sealed", "non_processed"} else 1


if __name__ == "__main__":
    raise SystemExit(main())