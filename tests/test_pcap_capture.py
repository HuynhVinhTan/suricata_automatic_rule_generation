"""Offline tests for bounded PCAP capture; tcpdump is always mocked."""
import hashlib
import json
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest

from backend import pcap_capture as capture


def _frame(flags=0x02):
    tcp = struct.pack("!HHIIBBHHH", 50000, 18100, 1, 0, 0x50, flags, 8192, 0, 0)
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 40, 0, 0x4000, 64, 6, 0,
        bytes((192, 168, 10, 20)), bytes((192, 168, 10, 10)),
    )
    return b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x00" + ip + tcp


def _pcap(frames=()):
    data = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
    for index, frame in enumerate(frames):
        data.extend(struct.pack("<IIII", index + 1, 0, len(frame), len(frame)))
        data.extend(frame)
    return bytes(data)


def _roots(tmp_path):
    capture_root = tmp_path / "private-captures"
    outbox = tmp_path / "outbox"
    capture_root.mkdir(mode=0o700)
    outbox.mkdir(mode=0o700)
    return capture_root, outbox


class _Tcpdump:
    def __init__(self, command, *, data, stop_cleanly=True, interrupt=False):
        self.command = command
        self.data = data
        self.stop_cleanly = stop_cleanly
        self.interrupt = interrupt
        self.returncode = None
        Path(command[command.index("-w") + 1]).write_bytes(data)

    def wait(self, timeout=None):
        if self.interrupt:
            self.interrupt = False
            raise KeyboardInterrupt
        if self.returncode is None and timeout == 60:
            raise capture.subprocess.TimeoutExpired("tcpdump", timeout)
        if self.returncode is None:
            if not self.stop_cleanly:
                raise capture.subprocess.TimeoutExpired("tcpdump", timeout)
            self.returncode = 0
        return self.returncode

    def send_signal(self, _signal):
        if self.stop_cleanly:
            self.returncode = 0

    def kill(self):
        self.returncode = -9


def _run(tmp_path, monkeypatch, data, *, run_id="capture-20261110T120000Z-0123456789abcdef", **kwargs):
    capture_root, outbox = _roots(tmp_path)
    monkeypatch.setattr(capture, "_new_run_id", lambda: run_id)
    monkeypatch.setattr(capture, "LINUX_CAPTURE", True)
    monkeypatch.setattr(capture, "_size_limit_preexec", lambda _limit: lambda: None)
    monkeypatch.setattr(
        capture.subprocess, "Popen",
        lambda command, **_options: _Tcpdump(command, data=data, **kwargs),
    )
    monkeypatch.setattr(capture.shutil, "disk_usage", lambda _path: SimpleNamespace(free=4 * 1024**3))
    return capture.capture_once(capture_root=capture_root, outbox=outbox), capture_root, outbox


def test_capture_seals_only_exact_bounded_filter_and_preserves_original(tmp_path, monkeypatch):
    commands = []
    capture_root, outbox = _roots(tmp_path)
    monkeypatch.setattr(capture, "_new_run_id", lambda: "capture-20261110T120000Z-0123456789abcdef")
    monkeypatch.setattr(capture, "LINUX_CAPTURE", True)
    monkeypatch.setattr(capture, "_size_limit_preexec", lambda _limit: lambda: None)

    def start(command, **options):
        commands.append(command)
        assert options["shell"] is False
        assert callable(options["preexec_fn"])
        return _Tcpdump(command, data=_pcap([_frame()]))

    monkeypatch.setattr(capture.subprocess, "Popen", start)
    monkeypatch.setattr(capture.shutil, "disk_usage", lambda _path: SimpleNamespace(free=4 * 1024**3))
    result = capture.capture_once(capture_root=capture_root, outbox=outbox)

    assert result["status"] == "sealed"
    assert commands[0][commands[0].index("-i") + 1] == "ens33"
    assert commands[0][commands[0].index("-s") + 1] == "262144"
    assert commands[0][-1] == "tcp and src host 192.168.10.20 and dst host 192.168.10.10"
    run_id = result["run_id"]
    assert (capture_root / run_id / "capture.pcap").read_bytes() == _pcap([_frame()])
    assert (outbox / run_id / f"{run_id}.ready.json").is_file()


@pytest.mark.parametrize("frames", [[], [_frame(flags=0x10)]])
def test_empty_or_no_syn_capture_is_preserved_but_not_sealed(tmp_path, monkeypatch, frames):
    result, root, outbox = _run(tmp_path, monkeypatch, _pcap(frames))

    assert result["status"] == "non_processed"
    assert (root / result["run_id"] / "capture.pcap").is_file()
    assert not list(outbox.rglob("*.ready.json"))
    assert json.loads((root / result["run_id"] / "status.json").read_text())["status"] == "non_processed"


@pytest.mark.parametrize("duration", [0, 61])
def test_duration_outside_safe_bounds_fails_before_capture(tmp_path, monkeypatch, duration):
    capture_root, outbox = _roots(tmp_path)
    monkeypatch.setattr(capture, "LINUX_CAPTURE", True)
    monkeypatch.setattr(capture.subprocess, "Popen", lambda *_args, **_kwargs: pytest.fail("must not start"))
    with pytest.raises(capture.CaptureError, match="duration"):
        capture.capture_once(capture_root=capture_root, outbox=outbox, duration_seconds=duration)


def test_corrupt_capture_is_preserved_without_ready_marker(tmp_path, monkeypatch):
    result, root, outbox = _run(tmp_path, monkeypatch, _pcap([_frame()])[:-1])

    assert result["status"] == "failed"
    assert (root / result["run_id"] / "capture.pcap").is_file()
    assert not list(outbox.rglob("*.ready.json"))


def test_capture_file_over_maximum_is_preserved_but_unsealed(tmp_path, monkeypatch):
    monkeypatch.setattr(capture, "MAX_PCAP_BYTES", 24)
    result, _root, outbox = _run(tmp_path, monkeypatch, _pcap([_frame()]))

    assert result["status"] == "failed"
    assert "size" in result["diagnostic"]
    assert not list(outbox.rglob("*.ready.json"))


def test_insufficient_disk_space_fails_before_launch(tmp_path, monkeypatch):
    capture_root, outbox = _roots(tmp_path)
    monkeypatch.setattr(capture, "LINUX_CAPTURE", True)
    monkeypatch.setattr(capture.shutil, "disk_usage", lambda _path: SimpleNamespace(free=3 * 1024**3 - 1))
    monkeypatch.setattr(capture.subprocess, "Popen", lambda *_args, **_kwargs: pytest.fail("must not start"))

    with pytest.raises(capture.CaptureError, match="3 GiB"):
        capture.capture_once(capture_root=capture_root, outbox=outbox)


def test_size_and_retention_limits_fail_closed(tmp_path, monkeypatch):
    capture_root, outbox = _roots(tmp_path)
    (capture_root / "capture-20261109T120000Z-0123456789abcdef").mkdir()
    monkeypatch.setattr(capture, "LINUX_CAPTURE", True)
    monkeypatch.setattr(capture, "MAX_RETAINED_RUNS", 1)
    monkeypatch.setattr(capture.shutil, "disk_usage", lambda _path: SimpleNamespace(free=4 * 1024**3))
    monkeypatch.setattr(capture.subprocess, "Popen", lambda *_args, **_kwargs: pytest.fail("must not start"))

    with pytest.raises(capture.CaptureError, match="retention"):
        capture.capture_once(capture_root=capture_root, outbox=outbox)


def test_retained_byte_limit_fails_closed(tmp_path, monkeypatch):
    capture_root, outbox = _roots(tmp_path)
    retained = capture_root / "capture-20261109T120000Z-0123456789abcdef"
    retained.mkdir()
    (retained / "evidence.bin").write_bytes(b"x" * 128)
    monkeypatch.setattr(capture, "LINUX_CAPTURE", True)
    monkeypatch.setattr(capture, "MAX_PCAP_BYTES", 64)
    monkeypatch.setattr(capture, "MAX_RETAINED_BYTES", 200)
    monkeypatch.setattr(capture.shutil, "disk_usage", lambda _path: SimpleNamespace(free=4 * 1024**3))
    monkeypatch.setattr(capture.subprocess, "Popen", lambda *_args, **_kwargs: pytest.fail("must not start"))

    with pytest.raises(capture.CaptureError, match="retention"):
        capture.capture_once(capture_root=capture_root, outbox=outbox)


def test_capture_that_cannot_stop_is_failed_and_unsealed(tmp_path, monkeypatch):
    result, root, outbox = _run(
        tmp_path, monkeypatch, _pcap([_frame()]), stop_cleanly=False,
    )

    assert result["status"] == "failed"
    assert not list(outbox.rglob("*.ready.json"))
    assert json.loads((root / result["run_id"] / "status.json").read_text())["status"] == "failed"


def test_interrupted_capture_is_preserved_without_ready_marker(tmp_path, monkeypatch):
    result, root, outbox = _run(
        tmp_path, monkeypatch, _pcap([_frame()]), interrupt=True,
    )

    assert result["status"] == "interrupted"
    assert (root / result["run_id"] / "capture.pcap").is_file()
    assert not list(outbox.rglob("*.ready.json"))


def test_permission_failure_is_recorded_without_bundle(tmp_path, monkeypatch):
    capture_root, outbox = _roots(tmp_path)
    run_id = "capture-20261110T120000Z-0123456789abcdef"
    monkeypatch.setattr(capture, "LINUX_CAPTURE", True)
    monkeypatch.setattr(capture, "_new_run_id", lambda: run_id)
    monkeypatch.setattr(capture, "_size_limit_preexec", lambda _limit: lambda: None)
    monkeypatch.setattr(capture.shutil, "disk_usage", lambda _path: SimpleNamespace(free=4 * 1024**3))
    monkeypatch.setattr(capture.subprocess, "Popen", lambda *_args, **_kwargs: (_ for _ in ()).throw(PermissionError("denied")))

    result = capture.capture_once(capture_root=capture_root, outbox=outbox)

    assert result["status"] == "failed"
    assert json.loads((capture_root / run_id / "status.json").read_text())["error_type"] == "PermissionError"
    assert not list(outbox.rglob("*.ready.json"))


def test_bpf_cannot_be_overridden_from_cli():
    with pytest.raises(SystemExit):
        capture.main(["--bpf", "ip"])


def test_invalid_generated_run_id_fails_before_creating_a_run(tmp_path, monkeypatch):
    capture_root, outbox = _roots(tmp_path)
    monkeypatch.setattr(capture, "LINUX_CAPTURE", True)
    monkeypatch.setattr(capture, "_new_run_id", lambda: "../unsafe")
    monkeypatch.setattr(capture.shutil, "disk_usage", lambda _path: SimpleNamespace(free=4 * 1024**3))

    with pytest.raises(capture.CaptureError, match="run ID"):
        capture.capture_once(capture_root=capture_root, outbox=outbox)

    assert list(capture_root.iterdir()) == []


def test_symlink_capture_root_is_rejected(tmp_path, monkeypatch):
    capture_root, outbox = _roots(tmp_path)
    link = tmp_path / "capture-link"
    try:
        link.symlink_to(capture_root, target_is_directory=True)
    except OSError:
        pytest.skip("Symlinks unavailable")
    monkeypatch.setattr(capture, "LINUX_CAPTURE", True)

    with pytest.raises(capture.CaptureError, match="Symlink"):
        capture.capture_once(capture_root=link, outbox=outbox)


def test_existing_capture_lock_blocks_an_overlapping_run(tmp_path, monkeypatch):
    capture_root, outbox = _roots(tmp_path)
    (capture_root / ".capture.lock").write_text("active", encoding="ascii")
    monkeypatch.setattr(capture, "LINUX_CAPTURE", True)
    monkeypatch.setattr(capture.shutil, "disk_usage", lambda _path: SimpleNamespace(free=4 * 1024**3))

    with pytest.raises(capture.CaptureError, match="lock"):
        capture.capture_once(capture_root=capture_root, outbox=outbox)


def test_successive_unique_runs_are_sealed_without_overwriting(tmp_path, monkeypatch):
    capture_root, outbox = _roots(tmp_path)
    run_ids = iter((
        "capture-20261110T120000Z-0123456789abcdef",
        "capture-20261110T120100Z-fedcba9876543210",
    ))
    monkeypatch.setattr(capture, "LINUX_CAPTURE", True)
    monkeypatch.setattr(capture, "_new_run_id", lambda: next(run_ids))
    monkeypatch.setattr(capture, "_size_limit_preexec", lambda _limit: lambda: None)
    monkeypatch.setattr(capture.shutil, "disk_usage", lambda _path: SimpleNamespace(free=4 * 1024**3))
    monkeypatch.setattr(
        capture.subprocess, "Popen",
        lambda command, **_options: _Tcpdump(command, data=_pcap([_frame()])),
    )

    first = capture.capture_once(capture_root=capture_root, outbox=outbox)
    second = capture.capture_once(capture_root=capture_root, outbox=outbox)

    assert first["status"] == second["status"] == "sealed"
    assert first["run_id"] != second["run_id"]
    assert (outbox / first["run_id"] / f"{first['run_id']}.ready.json").is_file()
    assert (outbox / second["run_id"] / f"{second['run_id']}.ready.json").is_file()


def test_repeat_runs_do_not_overwrite_and_duplicate_id_fails_closed(tmp_path, monkeypatch):
    capture_root, outbox = _roots(tmp_path)
    run_id = "capture-20261110T120000Z-0123456789abcdef"
    monkeypatch.setattr(capture, "LINUX_CAPTURE", True)
    monkeypatch.setattr(capture.shutil, "disk_usage", lambda _path: SimpleNamespace(free=4 * 1024**3))
    monkeypatch.setattr(capture, "_new_run_id", lambda: run_id)
    monkeypatch.setattr(capture, "_size_limit_preexec", lambda _limit: lambda: None)
    monkeypatch.setattr(capture.subprocess, "Popen", lambda command, **_options: _Tcpdump(command, data=_pcap([_frame()])))
    first = capture.capture_once(capture_root=capture_root, outbox=outbox)
    original = (outbox / run_id / f"{run_id}.pcap").read_bytes()

    with pytest.raises(capture.CaptureError, match="unique run ID"):
        capture.capture_once(capture_root=capture_root, outbox=outbox)

    assert hashlib.sha256((outbox / run_id / f"{run_id}.pcap").read_bytes()).digest() == hashlib.sha256(original).digest()
    assert first["status"] == "sealed"