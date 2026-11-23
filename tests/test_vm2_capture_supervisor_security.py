"""POSIX security tests for the fixed privileged VM2 capture entrypoint."""

import os
import importlib.util
from pathlib import Path
import signal
import stat
import subprocess
from types import SimpleNamespace

import pytest

_SUPERVISOR_PATH = Path(__file__).parents[1] / "scripts" / "demo" / "vm2-capture-supervisor.py"
_SPEC = importlib.util.spec_from_file_location("vm2_capture_supervisor", _SUPERVISOR_PATH)
supervisor = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(supervisor)


pytestmark = pytest.mark.skipif(os.name == "nt", reason="requires POSIX file modes and process groups")


def _secure_entrypoint(path: Path) -> Path:
    path.parent.mkdir(parents=True)
    path.write_text("#!/usr/bin/python3\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def test_rejects_writable_privileged_executable(tmp_path):
    entrypoint = _secure_entrypoint(tmp_path / "libexec" / "capture-supervisor")
    entrypoint.chmod(0o775)

    with pytest.raises(supervisor.CaptureSecurityError, match="privileged executable"):
        supervisor.validate_secure_installation(entrypoint, expected_uid=os.getuid(), stop_at=tmp_path)


def test_rejects_unsafe_privileged_ownership(tmp_path, monkeypatch):
    entrypoint = _secure_entrypoint(tmp_path / "libexec" / "capture-supervisor")
    real_stat = supervisor.os.stat

    def fake_stat(path, *args, **kwargs):
        result = real_stat(path, *args, **kwargs)
        if Path(path) == entrypoint:
            return SimpleNamespace(st_mode=result.st_mode, st_uid=os.getuid() + 1)
        return result

    monkeypatch.setattr(supervisor.os, "stat", fake_stat)
    with pytest.raises(supervisor.CaptureSecurityError, match="owned by uid"):
        supervisor.validate_secure_installation(entrypoint, expected_uid=os.getuid(), stop_at=tmp_path)


def test_rejects_writable_privileged_ancestor(tmp_path):
    parent = tmp_path / "libexec"
    entrypoint = _secure_entrypoint(parent / "capture-supervisor")
    parent.chmod(0o775)

    with pytest.raises(supervisor.CaptureSecurityError, match="ancestor"):
        supervisor.validate_secure_installation(entrypoint, expected_uid=os.getuid(), stop_at=tmp_path)


def test_rejects_privileged_entrypoint_from_alternate_path(tmp_path):
    alternate = _secure_entrypoint(tmp_path / "alternate" / "capture-supervisor")
    approved = tmp_path / "approved" / "capture-supervisor"

    with pytest.raises(supervisor.CaptureSecurityError, match="approved fixed path"):
        supervisor.validate_privileged_origin(
            alternate,
            install_path=approved,
            expected_uid=os.getuid(),
            stop_at=tmp_path,
        )


def test_privileged_entrypoint_declares_isolated_python_startup():
    assert _SUPERVISOR_PATH.read_text(encoding="utf-8").splitlines()[0] == "#!/usr/bin/python3 -I"


def test_unsafe_python_startup_configuration_cannot_run_alternate_entrypoint(tmp_path):
    alternate = tmp_path / "capture-supervisor"
    alternate.write_bytes(_SUPERVISOR_PATH.read_bytes())
    alternate.chmod(0o755)
    marker = tmp_path / "sitecustomize-ran"
    (tmp_path / "sitecustomize.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('unsafe')\n",
        encoding="utf-8",
    )
    env = dict(os.environ, PYTHONPATH=str(tmp_path), PYTHONHOME=str(tmp_path))
    result = subprocess.run(
        [str(alternate), "--output", "/home/kali/suricata-ai-showcase/evidence/attack-20261123T000000Z.pcap.partial.pcap", "--stop-file", "/home/kali/suricata-ai-showcase/evidence/attack-20261123T000000Z.pcap.stop"],
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 77
    assert not marker.exists()


def test_tcpdump_command_has_only_reviewed_fixed_scope():
    assert supervisor.build_tcpdump_command(17) == [
        "/usr/bin/tcpdump",
        "-i",
        "eth1",
        "-s",
        "96",
        "-n",
        "-U",
        "-w",
        "/proc/self/fd/17",
        "-c",
        "5000",
        supervisor.BPF,
    ]
    assert "192.168.10.20" in supervisor.BPF
    assert "192.168.10.10" in supervisor.BPF
    assert "18100-18123" in supervisor.BPF


def test_rejects_arbitrary_command_arguments():
    with pytest.raises(SystemExit):
        supervisor.main(
            [
                "--output",
                "/home/kali/suricata-ai-showcase/evidence/attack-20261123T000000Z.pcap.partial.pcap",
                "--stop-file",
                "/home/kali/suricata-ai-showcase/evidence/attack-20261123T000000Z.pcap.stop",
                "--",
                "/bin/sh",
            ]
        )


def test_rejects_extra_arguments_and_path_traversal(tmp_path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    evidence.chmod(0o700)
    output = evidence / "attack-20261123T000000Z.pcap.partial.pcap"
    stop = evidence / "attack-20261123T000000Z.pcap.stop"

    supervisor.validate_request_paths(output, stop, evidence)

    with pytest.raises(supervisor.CaptureSecurityError):
        supervisor.validate_request_paths(evidence / "nested" / output.name, stop, evidence)
    with pytest.raises(supervisor.CaptureSecurityError):
        supervisor.validate_request_paths(evidence / "attack-20261123T000000Z.pcap", stop, evidence)
    with pytest.raises(supervisor.CaptureSecurityError):
        supervisor.validate_request_paths(output, evidence / "other.stop", evidence)


def test_secure_output_refuses_existing_file_and_symlink(tmp_path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    evidence.chmod(0o700)
    output_name = "attack-20261123T000000Z.pcap.partial.pcap"
    output = evidence / output_name
    stop = evidence / "attack-20261123T000000Z.pcap.stop"
    supervisor.validate_request_paths(output, stop, evidence)

    output.write_bytes(b"existing")
    directory_fd = supervisor.open_evidence_directory(evidence)
    try:
        with pytest.raises(supervisor.CaptureSecurityError, match="exists"):
            supervisor.open_capture_output(directory_fd, output_name)
    finally:
        os.close(directory_fd)


def test_rejects_shared_evidence_directory(tmp_path):
    evidence = tmp_path / "evidence"
    evidence.mkdir(mode=0o755)
    with pytest.raises(supervisor.CaptureSecurityError, match="accessible to group or other"):
        supervisor.open_evidence_directory(evidence)


def test_completed_output_is_private_and_owned_by_evidence_user(tmp_path):
    evidence = tmp_path / "evidence"
    evidence.mkdir(mode=0o700)
    output_name = "attack-20261123T000000Z.pcap.partial.pcap"
    output = evidence / output_name
    stop = evidence / "attack-20261123T000000Z.pcap.stop"
    supervisor.validate_request_paths(output, stop, evidence)
    directory_fd = supervisor.open_evidence_directory(evidence)
    try:
        output_fd = supervisor.open_capture_output(directory_fd, output_name)
        try:
            output_stat = os.fstat(output_fd)
            supervisor.finalize_capture_output(directory_fd, output_fd, output_name, output_stat)
            final_stat = os.stat(output, follow_symlinks=False)
            assert stat.S_IMODE(final_stat.st_mode) == 0o600
            assert final_stat.st_uid == os.fstat(directory_fd).st_uid
        finally:
            os.close(output_fd)
    finally:
        os.close(directory_fd)

    output.unlink()
    output.symlink_to(tmp_path / "unrelated")
    directory_fd = supervisor.open_evidence_directory(evidence)
    try:
        with pytest.raises(supervisor.CaptureSecurityError):
            supervisor.open_capture_output(directory_fd, output_name)
    finally:
        os.close(directory_fd)


def test_finalization_refuses_replaced_output(tmp_path):
    evidence = tmp_path / "evidence"
    evidence.mkdir(mode=0o700)
    output_name = "attack-20261123T000000Z.pcap.partial.pcap"
    directory_fd = supervisor.open_evidence_directory(evidence)
    output_fd = supervisor.open_capture_output(directory_fd, output_name)
    try:
        output_stat = os.fstat(output_fd)
        (evidence / output_name).unlink()
        (evidence / output_name).write_bytes(b"replacement")
        with pytest.raises(supervisor.CaptureSecurityError, match="replaced or removed"):
            supervisor.finalize_capture_output(directory_fd, output_fd, output_name, output_stat)
    finally:
        os.close(output_fd)
        os.close(directory_fd)


def test_evidence_path_component_symlink_is_refused(tmp_path):
    real_root = tmp_path / "real-evidence"
    real_root.mkdir()
    linked_root = tmp_path / "evidence"
    linked_root.symlink_to(real_root, target_is_directory=True)

    with pytest.raises(supervisor.CaptureSecurityError):
        supervisor.open_evidence_directory(linked_root)


def test_process_group_stop_does_not_use_forged_pid_file(tmp_path):
    capture = subprocess.Popen(["sleep", "30"], start_new_session=True)
    unrelated = subprocess.Popen(["sleep", "30"], start_new_session=True)
    forged_pid_file = tmp_path / "capture.pid"
    forged_pid_file.write_text(str(unrelated.pid), encoding="utf-8")
    try:
        supervisor.stop_process_group(capture, signal.SIGTERM)
        assert capture.wait(timeout=3) is not None
        assert unrelated.poll() is None
    finally:
        if capture.poll() is None:
            supervisor.stop_process_group(capture, signal.SIGKILL)
        if unrelated.poll() is None:
            supervisor.stop_process_group(unrelated, signal.SIGKILL)
