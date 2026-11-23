import os
import json
import hashlib
from pathlib import Path, PurePosixPath
import shutil
import subprocess

import pytest

from scripts.runtime_orchestration_contract import (
    CAPTURE_SERVICE,
    build_vm1_capture_readiness_script,
    build_worker_argv,
    capture_bundle_paths,
    correlate_capture_and_generator,
    g3_release_paths,
    validate_capture_generator_evidence,
    worker_bundle_paths,
)


def test_capture_readiness_is_nonblocking_and_never_launches_generator():
    script = build_vm1_capture_readiness_script()
    assert f"sudo systemctl start --no-block {CAPTURE_SERVICE}" in script
    assert "ActiveState" in script and "SubState" in script
    assert "[/]tcpdump" in script
    assert "[t]cpdump" not in script
    assert "lab_slow_port_scan" not in script
    assert "python" not in script
    assert "systemctl start " + CAPTURE_SERVICE + "\n" not in script


def test_mock_oneshot_activating_start_with_capture_process_reaches_ready(tmp_path):
    result = _run_mock_readiness(tmp_path, state="activating", substate="start", process=True, now=1001)
    assert result.returncode == 0, result.stderr
    assert "G2_CAPTURE_READY=TRUE" in result.stdout


def test_mock_oneshot_missing_capture_process_never_runs_followup_generator(tmp_path):
    sentinel = tmp_path / "generator-ran"
    result = _run_mock_readiness(
        tmp_path, state="activating", substate="start", process=False, now=1061,
        followup=f"printf ran > {sentinel}",
    )
    assert result.returncode != 0
    assert "G2_CAPTURE_READY=TRUE" not in result.stdout
    assert not sentinel.exists()


@pytest.mark.parametrize(
    ("state", "substate"),
    (("inactive", "dead"), ("failed", "failed"), ("active", "exited")),
)
def test_mock_oneshot_completed_or_failed_state_is_not_ready(tmp_path, state, substate):
    result = _run_mock_readiness(tmp_path, state=state, substate=substate, process=True, now=1001)
    assert result.returncode != 0
    assert "G2_CAPTURE_READY=TRUE" not in result.stdout


def test_mock_oneshot_deadline_is_not_ready_even_with_capture_process(tmp_path):
    result = _run_mock_readiness(tmp_path, state="activating", substate="start", process=True, now=1060)
    assert result.returncode != 0
    assert "G2_CAPTURE_READY=TRUE" not in result.stdout


def _run_mock_readiness(tmp_path: Path, *, state: str, substate: str, process: bool,
                        now: int, followup: str = ""):
    bash = shutil.which("bash")
    if bash is None or os.name == "nt":
        pytest.skip("requires POSIX Bash for executable mock-systemd test")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _mock_command(bin_dir / "sudo", '#!/bin/sh\nshift\nexec "$@"\n')
    _mock_command(bin_dir / "systemctl", '''#!/bin/sh
case "$1" in
  start) exit 0 ;;
  show)
    case "$3" in
      ActiveState) printf '%s\\n' "$MOCK_STATE" ;;
      SubState) printf '%s\\n' "$MOCK_SUBSTATE" ;;
    esac
    ;;
  status) exit 0 ;;
  *) exit 2 ;;
esac
''')
    _mock_command(bin_dir / "pgrep", '#!/bin/sh\n[ "${MOCK_PROCESS:-0}" = 1 ]\n')
    date_counter = tmp_path / "date-counter"
    _mock_command(bin_dir / "date", f'''#!/bin/sh
if [ ! -e {date_counter} ]; then printf 1 > {date_counter}; printf '%s\\n' "$MOCK_START";
else printf '%s\\n' "$MOCK_NOW"; fi
''')
    _mock_command(bin_dir / "sleep", '#!/bin/sh\nexit 0\n')
    script = build_vm1_capture_readiness_script() + (f"\n{followup}\n" if followup else "")
    env = os.environ.copy()
    env.update({
        "PATH": str(bin_dir) + os.pathsep + env.get("PATH", ""),
        "MOCK_STATE": state,
        "MOCK_SUBSTATE": substate,
        "MOCK_PROCESS": "1" if process else "0",
        "MOCK_START": "1000",
        "MOCK_NOW": str(now),
    })
    return subprocess.run([bash, "-c", script], capture_output=True, text=True, env=env, check=False)


def _mock_command(path: Path, content: str):
    path.write_text(content, encoding="utf-8")
    path.chmod(0o700)


def test_sealed_bundle_paths_use_backend_capture_id():
    paths = capture_bundle_paths("capture-20261123T120000Z-0123456789abcdef")
    assert paths == (
        "/home/tanhv/suricata-ai-outbox/capture-20261123T120000Z-0123456789abcdef/"
        "capture-20261123T120000Z-0123456789abcdef.pcap",
        "/home/tanhv/suricata-ai-outbox/capture-20261123T120000Z-0123456789abcdef/"
        "capture-20261123T120000Z-0123456789abcdef.manifest.json",
        "/home/tanhv/suricata-ai-outbox/capture-20261123T120000Z-0123456789abcdef/"
        "capture-20261123T120000Z-0123456789abcdef.ready.json",
    )
    assert all("capture.pcap" not in path for path in paths)
    with pytest.raises(ValueError):
        capture_bundle_paths("g4-attack-20261123T120000Z-0123456789abcdef")


def test_vm3_worker_bundle_is_flat_after_handoff():
    paths = worker_bundle_paths(
        "capture-20261123T120000Z-0123456789abcdef",
        input_root=PurePosixPath("/home/tanhv/verified-inbox"),
    )
    assert paths == (
        "/home/tanhv/verified-inbox/capture-20261123T120000Z-0123456789abcdef.pcap",
        "/home/tanhv/verified-inbox/capture-20261123T120000Z-0123456789abcdef.manifest.json",
        "/home/tanhv/verified-inbox/capture-20261123T120000Z-0123456789abcdef.ready.json",
    )
    assert all("/capture-20261123T120000Z-0123456789abcdef/" not in path for path in paths)


def test_capture_and_generator_identity_are_correlated_not_renamed():
    result = correlate_capture_and_generator(
        "capture-20261123T120000Z-0123456789abcdef",
        "g4-attack-20261123T120001Z-fedcba9876543210",
    )
    assert result["capture_id"].startswith("capture-")
    assert result["generator_id"].startswith("g4-")
    with pytest.raises(ValueError):
        correlate_capture_and_generator(
            "capture-20261123T120000Z-0123456789abcdef",
            "capture-20261123T120000Z-0123456789abcdef",
        )


def test_worker_argv_has_input_root_manifest_and_private_root():
    argv = build_worker_argv(
        "capture-20261123T120000Z-0123456789abcdef",
        input_root=PurePosixPath("/home/tanhv/ai-inbox"),
        private_root=PurePosixPath("/home/tanhv/ai-private"),
    )
    assert argv[0:3] == ["/home/tanhv/suricata-ai-venv/bin/python", "-m", "backend.worker"]
    assert "--input-root" in argv
    assert "--private-root" in argv
    assert "--manifest" in argv
    assert "capture.pcap" not in argv
    assert argv[argv.index("--run-id") + 1] == "capture-20261123T120000Z-0123456789abcdef"
    assert argv[argv.index("--pcap") + 1] == (
        "/home/tanhv/ai-inbox/capture-20261123T120000Z-0123456789abcdef.pcap"
    )
    assert argv[argv.index("--manifest") + 1] == (
        "/home/tanhv/ai-inbox/capture-20261123T120000Z-0123456789abcdef.manifest.json"
    )


def test_g3_sync_is_versioned_and_private_key_is_not_in_release():
    paths = g3_release_paths(
        host_root=PurePosixPath("/home/tanhv/suricata-ai-showcase"),
        release_sha="d1005c24f94c3d994a9fff7cdb780c4ca90b3daa",
    )
    assert paths["release"].endswith("/releases/d1005c24f94c3d994a9fff7cdb780c4ca90b3daa")
    assert "/current/" not in paths["release"]
    assert paths["private_key"].endswith("/private/g3/g3-signer.pem")
    assert paths["private_key"] not in paths["release"]
    assert paths["ledger"].endswith("/private/g3/g3-replay.sqlite3")
    assert paths["fingerprint"].endswith("/private/g3/g3-signer.pub.sha256")
    assert paths["record"].endswith("/evidence/g3/record.json")


def test_capture_generator_correlation_checks_hashes_timestamps_tuples_and_counts():
    capture_id = "capture-20261123T120000Z-0123456789abcdef"
    generator_id = "g4-attack-20261123T120001Z-fedcba9876543210"
    pcap = b"verified pcap"
    native = {
        "run_id": capture_id,
        "pcap_sha256": hashlib.sha256(pcap).hexdigest(),
        "source_ipv4": "192.168.10.20",
        "destination_ipv4": "192.168.10.10",
        "capture_metadata": {
            "packets": 24,
            "initial_syn": 24,
            "sealed_at": "2026-11-23T12:02:00Z",
        },
    }
    native_bytes = json.dumps(native, sort_keys=True, separators=(",", ":")).encode()
    attempts = [{
        "source_ip": "192.168.10.20",
        "destination_ip": "192.168.10.10",
        "source_port": 40000 + index,
        "destination_port": 18100 + index,
    } for index in range(24)]
    generator = {
        "run_id": generator_id,
        "scenario": "ATTACK",
        "source_ip": "192.168.10.20",
        "target_ip": "192.168.10.10",
        "started_at_utc": "2026-11-23T12:00:01Z",
        "ended_at_utc": "2026-11-23T12:01:00Z",
        "attempt_count": 24,
        "attempts": attempts,
    }
    generator_bytes = json.dumps(generator, sort_keys=True, separators=(",", ":")).encode()
    ready = {
        "run_id": capture_id,
        "pcap_sha256": native["pcap_sha256"],
        "manifest_sha256": hashlib.sha256(native_bytes).hexdigest(),
    }
    result = validate_capture_generator_evidence(
        scenario="ATTACK",
        capture_id=capture_id,
        generator_id=generator_id,
        pcap_bytes=pcap,
        native_manifest_bytes=native_bytes,
        native_manifest=native,
        ready_marker=ready,
        generator_bytes=generator_bytes,
    )
    assert result["capture_id"] == capture_id
    assert result["generator_id"] == generator_id
    assert result["pcap_sha256"] == native["pcap_sha256"]
    assert result["generator_sha256"] == hashlib.sha256(generator_bytes).hexdigest()


def test_capture_generator_correlation_rejects_tuple_or_timestamp_mismatch():
    native = {
        "run_id": "capture-20261123T120000Z-0123456789abcdef",
        "pcap_sha256": "a" * 64,
        "source_ipv4": "192.168.10.20",
        "destination_ipv4": "192.168.10.10",
        "capture_metadata": {"packets": 1, "initial_syn": 1, "sealed_at": "2026-11-23T12:00:00Z"},
    }
    generator = {
        "run_id": "g4-attack-20261123T120001Z-fedcba9876543210",
        "scenario": "ATTACK",
        "source_ip": "192.168.10.20",
        "target_ip": "192.168.10.10",
        "started_at_utc": "2026-11-23T12:01:00Z",
        "ended_at_utc": "2026-11-23T12:02:00Z",
        "attempt_count": 1,
        "attempts": [{
            "source_ip": "192.168.10.20",
            "destination_ip": "192.168.10.99",
            "source_port": 40000,
            "destination_port": 18100,
        }],
    }
    pcap = b"pcap"
    native["pcap_sha256"] = hashlib.sha256(pcap).hexdigest()
    native_bytes = json.dumps(native, sort_keys=True, separators=(",", ":")).encode()
    ready = {
        "run_id": native["run_id"],
        "pcap_sha256": native["pcap_sha256"],
        "manifest_sha256": hashlib.sha256(native_bytes).hexdigest(),
    }
    with pytest.raises(ValueError, match="tuple|timestamp|count"):
        validate_capture_generator_evidence(
            scenario="ATTACK",
            capture_id=native["run_id"],
            generator_id=generator["run_id"],
            pcap_bytes=pcap,
            native_manifest_bytes=native_bytes,
            native_manifest=native,
            ready_marker=ready,
            generator_bytes=json.dumps(generator).encode(),
        )
