#!/usr/bin/python3 -I
"""Fixed-scope privileged VM2 tcpdump supervisor."""

from __future__ import annotations

import argparse
import errno
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time


INSTALL_PATH = Path("/usr/local/libexec/suricata-ai-showcase/vm2-capture-supervisor")
INSTALLATION_OWNER_UID = 0
INSTALLATION_VALIDATION_BOUNDARY: Path | None = None
EVIDENCE_ROOT = Path("/home/kali/suricata-ai-showcase/evidence")
TCPDUMP = "/usr/bin/tcpdump"
IFACE = "eth1"
SOURCE_IP = "192.168.10.20"
TARGET_IP = "192.168.10.10"
MAX_SECONDS = 120
MAX_PACKETS = 5000
SNAPLEN = 96
BPF = (
    "((src host 192.168.10.20 and dst host 192.168.10.10 and tcp and "
    "dst portrange 18100-18123) or (src host 192.168.10.10 and "
    "dst host 192.168.10.20 and tcp and src portrange 18100-18123))"
)
OUTPUT_NAME = re.compile(r"^attack-[0-9]{8}T[0-9]{6}Z\.pcap\.partial\.pcap$")
FINAL_OUTPUT_MODE = 0o600


class CaptureSecurityError(RuntimeError):
    """Raised when a privileged boundary or output invariant is unsafe."""


def validate_privileged_origin(
    path: Path | None = None,
    *,
    install_path: Path = INSTALL_PATH,
    expected_uid: int = INSTALLATION_OWNER_UID,
    stop_at: Path | None = INSTALLATION_VALIDATION_BOUNDARY,
) -> None:
    """Require this executable to be the exact approved fixed installation."""

    path = Path(__file__) if path is None else Path(path)
    install_path = Path(install_path)
    if path != install_path:
        raise CaptureSecurityError(f"privileged executable is not at the approved fixed path: {path}")
    validate_secure_installation(path, expected_uid=expected_uid, stop_at=stop_at)


def validate_secure_installation(
    path: Path,
    *,
    expected_uid: int = 0,
    stop_at: Path | None = None,
) -> None:
    """Require an executable owned by the expected uid with safe ancestors."""

    path = Path(path)
    try:
        file_stat = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise CaptureSecurityError(f"privileged executable is unavailable: {path}") from exc
    if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_uid != expected_uid:
        raise CaptureSecurityError(f"privileged executable is not owned by uid {expected_uid}: {path}")
    if not file_stat.st_mode & stat.S_IXUSR or file_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise CaptureSecurityError(f"privileged executable is writable or not executable: {path}")

    boundary = Path(stop_at).resolve() if stop_at else Path(path.anchor)
    current = path.parent
    while True:
        try:
            directory_stat = os.stat(current, follow_symlinks=False)
        except OSError as exc:
            raise CaptureSecurityError(f"privileged executable ancestor is unavailable: {current}") from exc
        if not stat.S_ISDIR(directory_stat.st_mode):
            raise CaptureSecurityError(f"privileged executable ancestor is not a directory: {current}")
        if directory_stat.st_uid != expected_uid or directory_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise CaptureSecurityError(f"privileged executable ancestor is writable: {current}")
        if current == boundary or current == Path(current.anchor):
            break
        current = current.parent


def validate_request_paths(output: Path, stop_file: Path, evidence_root: Path = EVIDENCE_ROOT) -> None:
    """Accept only a direct timestamped evidence output and matching stop marker."""

    output = Path(output)
    stop_file = Path(stop_file)
    evidence_root = Path(evidence_root)
    if not output.is_absolute() or not stop_file.is_absolute():
        raise CaptureSecurityError("capture paths must be absolute")
    if output.parent != evidence_root or stop_file.parent != evidence_root:
        raise CaptureSecurityError("capture paths must stay in the evidence directory")
    if not OUTPUT_NAME.fullmatch(output.name):
        raise CaptureSecurityError("capture output name is outside the approved format")
    expected_stop = output.name.removesuffix(".partial.pcap") + ".stop"
    if stop_file.name != expected_stop:
        raise CaptureSecurityError("stop request does not match the capture output")


def open_evidence_directory(evidence_root: Path = EVIDENCE_ROOT) -> int:
    """Open every fixed path component without following symlinks."""

    evidence_root = Path(evidence_root)
    if not evidence_root.is_absolute():
        raise CaptureSecurityError("evidence root must be absolute")
    directory_fd = -1
    try:
        directory_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        for component in evidence_root.parts[1:]:
            next_fd = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=directory_fd,
            )
            os.close(directory_fd)
            directory_fd = next_fd
    except OSError as exc:
        if directory_fd >= 0:
            os.close(directory_fd)
        raise CaptureSecurityError(f"evidence directory is not a safe directory: {evidence_root}") from exc
    directory_stat = os.fstat(directory_fd)
    if not stat.S_ISDIR(directory_stat.st_mode):
        os.close(directory_fd)
        raise CaptureSecurityError("evidence root is not a directory")
    if directory_stat.st_mode & 0o077:
        os.close(directory_fd)
        raise CaptureSecurityError("evidence directory is accessible to group or other users")
    return directory_fd


def open_capture_output(directory_fd: int, output_name: str) -> int:
    """Create a new output inode and refuse existing files, links or overwrites."""

    try:
        return os.open(
            output_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o644,
            dir_fd=directory_fd,
        )
    except OSError as exc:
        if exc.errno in (errno.EEXIST, errno.ELOOP):
            raise CaptureSecurityError("capture output already exists or is a symlink") from exc
        raise CaptureSecurityError("capture output cannot be created safely") from exc


def build_tcpdump_command(output_fd: int) -> list[str]:
    """Build the only tcpdump command this privileged entrypoint can execute."""

    return [
        TCPDUMP,
        "-i",
        IFACE,
        "-s",
        str(SNAPLEN),
        "-n",
        "-U",
        "-w",
        f"/proc/self/fd/{output_fd}",
        "-c",
        str(MAX_PACKETS),
        BPF,
    ]


def stop_process_group(process: subprocess.Popen[object], signum: signal.Signals) -> None:
    """Signal only the process group created by this supervisor."""

    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signum)
    except ProcessLookupError:
        return


def _stop_and_reap(process: subprocess.Popen[object]) -> bool:
    for signum, wait_seconds in (
        (signal.SIGINT, 3.0),
        (signal.SIGTERM, 1.0),
        (signal.SIGKILL, 1.0),
    ):
        if process.poll() is not None:
            return True
        stop_process_group(process, signum)
        try:
            process.wait(timeout=wait_seconds)
            return True
        except subprocess.TimeoutExpired:
            continue
    return process.poll() is not None


def _entry_exists(directory_fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return True


def _same_inode(directory_fd: int, name: str, output_stat: os.stat_result) -> bool:
    try:
        path_stat = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError:
        return False
    return (
        stat.S_ISREG(path_stat.st_mode)
        and path_stat.st_dev == output_stat.st_dev
        and path_stat.st_ino == output_stat.st_ino
    )


def finalize_capture_output(
    directory_fd: int,
    output_fd: int,
    output_name: str,
    output_stat: os.stat_result,
) -> None:
    """Make a completed capture private and readable by the evidence owner."""

    if not _same_inode(directory_fd, output_name, output_stat):
        raise CaptureSecurityError("output path was replaced or removed")
    directory_stat = os.fstat(directory_fd)
    if not stat.S_ISDIR(directory_stat.st_mode):
        raise CaptureSecurityError("evidence root is not a directory")
    try:
        os.fchown(output_fd, directory_stat.st_uid, directory_stat.st_gid)
        os.fchmod(output_fd, FINAL_OUTPUT_MODE)
    except OSError as exc:
        raise CaptureSecurityError("completed capture ownership or mode could not be secured") from exc
    final_stat = os.fstat(output_fd)
    if (
        final_stat.st_uid != directory_stat.st_uid
        or final_stat.st_gid != directory_stat.st_gid
        or final_stat.st_mode & 0o077
        or not _same_inode(directory_fd, output_name, final_stat)
    ):
        raise CaptureSecurityError("completed capture ownership or mode is unsafe")


def run_capture(output: Path, stop_file: Path, evidence_root: Path = EVIDENCE_ROOT) -> int:
    validate_request_paths(output, stop_file, evidence_root)
    directory_fd = -1
    output_fd = -1
    process: subprocess.Popen[object] | None = None
    interrupted = False

    def on_signal(_signum: int, _frame: object) -> None:
        nonlocal interrupted
        interrupted = True

    previous_int = signal.signal(signal.SIGINT, on_signal)
    previous_term = signal.signal(signal.SIGTERM, on_signal)
    try:
        validate_privileged_origin()
        directory_fd = open_evidence_directory(evidence_root)
        output_fd = open_capture_output(directory_fd, output.name)
        output_stat = os.fstat(output_fd)
        process = subprocess.Popen(
            build_tcpdump_command(output_fd),
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            pass_fds=(output_fd,),
            start_new_session=True,
        )
        deadline = time.monotonic() + MAX_SECONDS
        stop_requested = False
        timed_out = False
        while process.poll() is None:
            if interrupted or _entry_exists(directory_fd, stop_file.name):
                stop_requested = True
                break
            if time.monotonic() >= deadline:
                timed_out = True
                break
            time.sleep(0.1)

        if process.poll() is None and (stop_requested or timed_out):
            if not _stop_and_reap(process):
                return 125
        status = process.wait()
        try:
            finalize_capture_output(directory_fd, output_fd, output.name, output_stat)
        except CaptureSecurityError as exc:
            print(f"CAPTURE_BLOCKED: {exc}", file=sys.stderr)
            return 125
        if timed_out:
            return 124
        return status
    except CaptureSecurityError as exc:
        print(f"CAPTURE_BLOCKED: {exc}", file=sys.stderr)
        return 77
    except OSError as exc:
        print(f"CAPTURE_BLOCKED: privileged capture could not start: {exc}", file=sys.stderr)
        return 77
    finally:
        if process is not None and process.poll() is None:
            _stop_and_reap(process)
        if output_fd >= 0:
            os.close(output_fd)
        if directory_fd >= 0:
            os.close(directory_fd)
        signal.signal(signal.SIGINT, previous_int)
        signal.signal(signal.SIGTERM, previous_term)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--stop-file", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        validate_request_paths(args.output, args.stop_file)
    except CaptureSecurityError as exc:
        print(f"CAPTURE_BLOCKED: {exc}", file=sys.stderr)
        return 77
    return run_capture(args.output, args.stop_file)


if __name__ == "__main__":
    raise SystemExit(main())
