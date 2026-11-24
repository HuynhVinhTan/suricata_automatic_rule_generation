import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts/g4_retarget_vm1_capture_dropin.ps1"
TARGET_WD = "/srv/approved-release"
ORIGINAL_WD = "/srv/old-tools"


def _extract_payload(action: str, values: dict[str, str]) -> str:
    source = SCRIPT.read_text(encoding="utf-8")
    start = source.index("$template = @'")
    body_start = source.index("\n", start) + 1
    end = source.index("\n'@", body_start)
    payload = source[body_start:end].replace("__ACTION__", action)
    for key, value in sorted(values.items(), key=lambda item: len(item[0]), reverse=True):
        payload = payload.replace(key, value)
    return payload.replace("\r\n", "\n")


def _bash_command() -> list[str]:
    if os.name != "nt":
        return ["bash", "-s"]
    return ["wsl.exe", "bash", "-s"]


def _wsl_path(path: Path) -> str:
    if os.name != "nt":
        return str(path)
    windows_path = str(path).replace("\\", "/")
    drive, rest = windows_path.split(":", 1)
    return f"/mnt/{drive.lower()}{rest}"


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8", newline="\n")
    path.chmod(0o755)


def _fixture(
    tmp_path: Path,
    *,
    action: str = "install",
    release: bool = True,
    initial_wd: str = ORIGINAL_WD,
    dropin_content: str | None = None,
    preexisting_dropin_dir: bool = False,
    fail_install: bool = False,
    fail_reload_once: bool = False,
    mutate_after_reload: bool = False,
    replace_after_reload: bool = False,
):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    state_path = tmp_path / "state.json"
    unit = tmp_path / "unit.service"
    unit.write_text("approved unit\n", encoding="utf-8")
    release_root = tmp_path / "release"
    if release:
        (release_root / "backend").mkdir(parents=True)
        (release_root / "backend/pcap_capture.py").write_text(
            "INTERFACE='ens33'\nDEFAULT_DURATION_SECONDS=60\n"
            "MAX_DURATION_SECONDS=60\nSNAPLEN=262144\n"
            "MAX_PCAP_BYTES=64 * 1024 * 1024\n"
            "BPF_FILTER='tcp and host 192.168.10.20 and host 192.168.10.10 and '\n"
            "'(port 18080 or portrange 18100-18123)'\n",
            encoding="utf-8",
        )
        (release_root / "backend/pcap_handoff.py").write_text(
            "# approved\n", encoding="utf-8"
        )

    dropin_dir = tmp_path / "dropin.d"
    dropin = dropin_dir / "10-g4-release.conf"
    if dropin_content is not None or preexisting_dropin_dir:
        dropin_dir.mkdir()
    if dropin_content is not None:
        dropin.write_text(dropin_content, encoding="utf-8", newline="\n")

    fields = {
        "ExecStart": "/usr/bin/python3 -m backend.pcap_capture",
        "ExecStartPre": "",
        "ExecStartPost": "",
        "User": "tanhv",
        "Group": "tanhv",
        "CapabilityBoundingSet": "CAP_NET_RAW",
        "AmbientCapabilities": "CAP_NET_RAW",
        "NoNewPrivileges": "yes",
        "ProtectSystem": "strict",
        "ProtectHome": "read-only",
        "PrivateTmp": "yes",
        "RestrictAddressFamilies": "AF_UNIX AF_INET AF_INET6",
        "ReadWritePaths": "/var/lib/suricata-ai-capture",
        "TimeoutStartUSec": "1min 30s",
        "WorkingDirectory": initial_wd,
        "ActiveState": "inactive",
        "SubState": "dead",
        "DropInPaths": str(dropin) if dropin.exists() else "",
    }
    state_path.write_text(
        json.dumps({"fields": fields, "reloads": 0}), encoding="utf-8"
    )

    _write_executable(
        fake_bin / "sudo",
        """#!/usr/bin/env python3
import os
import subprocess
import sys

args = sys.argv[1:]
if args and args[0] == '-n':
    args = args[1:]
if args and args[0] == 'install':
    if os.environ.get('FAKE_FAIL_INSTALL') == '1' and '-d' not in args:
        raise SystemExit(1)
    filtered = [args[0]]
    index = 1
    while index < len(args):
        if args[index] in ('-o', '-g'):
            index += 2
        else:
            filtered.append(args[index])
            index += 1
    args = filtered
raise SystemExit(subprocess.call(args))
""",
    )
    _write_executable(
        fake_bin / "pgrep",
        """#!/bin/sh
exit 1
""",
    )
    _write_executable(
        fake_bin / "stat",
        """#!/usr/bin/env python3
import os
import sys
if sys.argv[1] == '-c':
    print('root:root 755' if os.path.basename(sys.argv[-1]) == 'dropin.d' else 'root:root 644')
else:
    raise SystemExit('unsupported stat invocation')
""",
    )
    _write_executable(
        fake_bin / "systemctl",
        """#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

state_path = Path(os.environ['FAKE_STATE'])
data = json.loads(state_path.read_text())
fields = data['fields']
args = sys.argv[1:]
if args and args[0] == 'daemon-reload':
    data['reloads'] += 1
    if os.environ.get('FAKE_FAIL_RELOAD_ONCE') == '1' and data['reloads'] == 1:
        state_path.write_text(json.dumps(data))
        raise SystemExit(1)
    if os.environ.get('FAKE_MUTATE_AFTER_RELOAD') == '1':
        fields['User'] = 'unexpected-user'
    else:
        dropin = Path(os.environ['FAKE_DROPIN'])
        if os.environ.get('FAKE_REPLACE_DROPIN') == '1':
            dropin.write_text('unexpected replacement\\n')
        fields['WorkingDirectory'] = os.environ['FAKE_TARGET_WD'] if dropin.exists() else os.environ['FAKE_ORIGINAL_WD']
    fields['DropInPaths'] = str(Path(os.environ['FAKE_DROPIN'])) if Path(os.environ['FAKE_DROPIN']).exists() else ''
    state_path.write_text(json.dumps(data))
    raise SystemExit(0)
if args and args[0] == 'show':
    prop = args[args.index('-p') + 1]
    if prop == 'ActiveState' and args[-1] == 'suricata-ai-send.service':
        print('inactive')
    elif prop == 'ActiveState' and args[-1] == 'suricata-ai-send.timer':
        print('inactive')
    else:
        print(fields.get(prop, ''))
    raise SystemExit(0)
raise SystemExit('unsupported systemctl invocation')
""",
    )

    actual_unit = hashlib.sha256(unit.read_bytes()).hexdigest()
    capture_hash = (
        hashlib.sha256((release_root / "backend/pcap_capture.py").read_bytes()).hexdigest()
        if release
        else "0" * 64
    )
    handoff_hash = (
        hashlib.sha256((release_root / "backend/pcap_handoff.py").read_bytes()).hexdigest()
        if release
        else "0" * 64
    )
    expected_dropin = f"[Service]\nWorkingDirectory={release_root}\n"
    unit_value = _wsl_path(unit)
    release_value = _wsl_path(release_root)
    dropin_dir_value = _wsl_path(dropin_dir)
    dropin_value = _wsl_path(dropin)
    expected_dropin = f"[Service]\nWorkingDirectory={release_value}\n"
    dropin_hash = hashlib.sha256(expected_dropin.encode()).hexdigest()
    if dropin_content is not None and os.name == "nt":
        dropin.write_text(
            dropin_content.replace(str(release_root), release_value),
            encoding="utf-8",
            newline="\n",
        )
    values = {
        "__UNIT_SHA256__": actual_unit,
        "__CAPTURE_SHA256__": capture_hash,
        "__HANDOFF_SHA256__": handoff_hash,
        "__DROPIN_SHA256__": dropin_hash,
        "__ORIGINAL_WD__": ORIGINAL_WD,
        "__RELEASE__": release_value,
        "__BPF__": "tcp and host 192.168.10.20 and host 192.168.10.10 and (port 18080 or portrange 18100-18123)",
        "/etc/systemd/system/suricata-ai-capture.service": unit_value,
        "/etc/systemd/system/suricata-ai-capture.service.d": dropin_dir_value,
        "DROPIN=/etc/systemd/system/suricata-ai-capture.service.d/10-g4-release.conf": f"DROPIN={dropin_value}",
    }
    payload = _extract_payload(action, values)
    if os.name == "nt":
        prefix = (
            f"export PATH='{_wsl_path(fake_bin)}':$PATH\n"
            f"export FAKE_STATE='{_wsl_path(state_path)}'\n"
            f"export FAKE_DROPIN='{_wsl_path(dropin)}'\n"
            f"export FAKE_TARGET_WD='{_wsl_path(release_root)}'\n"
            f"export FAKE_ORIGINAL_WD='{ORIGINAL_WD}'\n"
        )
    else:
        prefix = (
            f"export PATH='{fake_bin}':$PATH\n"
            f"export FAKE_STATE='{state_path}'\n"
            f"export FAKE_DROPIN='{dropin}'\n"
            f"export FAKE_TARGET_WD='{release_root}'\n"
            f"export FAKE_ORIGINAL_WD='{ORIGINAL_WD}'\n"
        )
    if fail_reload_once:
        prefix += "export FAKE_FAIL_RELOAD_ONCE=1\n"
    if fail_install:
        prefix += "export FAKE_FAIL_INSTALL=1\n"
    if mutate_after_reload:
        prefix += "export FAKE_MUTATE_AFTER_RELOAD=1\n"
    if replace_after_reload:
        prefix += "export FAKE_REPLACE_DROPIN=1\n"
    result = subprocess.run(
        _bash_command(),
        input=(prefix + payload).replace("\r\n", "\n").encode(),
        text=False,
        capture_output=True,
        env=os.environ.copy(),
    )
    result.stdout = result.stdout.decode()
    result.stderr = result.stderr.decode()
    return result, dropin, dropin_dir


def test_successful_installation_is_executable_and_seals_exact_dropin(tmp_path):
    result, dropin, dropin_dir = _fixture(tmp_path)

    assert result.returncode == 0, result.stderr + result.stdout
    assert "VM1_CAPTURE_DROPIN_INSTALL_PASS=TRUE" in result.stdout
    expected_release = _wsl_path(tmp_path / "release") if os.name == "nt" else str(tmp_path / "release")
    assert dropin.read_text(encoding="utf-8") == f"[Service]\nWorkingDirectory={expected_release}\n"
    assert dropin_dir.exists()


def test_preflight_rejection_does_not_mutate_dropin_scope(tmp_path):
    result, dropin, dropin_dir = _fixture(tmp_path, release=False)

    assert result.returncode != 0
    assert not dropin.exists()
    assert not dropin_dir.exists()
    assert "unbound variable" not in (result.stdout + result.stderr)


def test_installation_failure_rolls_back_created_dropin(tmp_path):
    result, dropin, dropin_dir = _fixture(tmp_path, fail_reload_once=True)

    assert result.returncode != 0
    assert "VM1_CAPTURE_DROPIN_ROLLBACK_PASS=TRUE" in result.stdout
    assert not dropin.exists()
    assert not dropin_dir.exists()


def test_dropin_file_install_failure_rolls_back_created_directory(tmp_path):
    result, dropin, dropin_dir = _fixture(tmp_path, fail_install=True)

    assert result.returncode != 0
    assert "VM1_CAPTURE_DROPIN_ROLLBACK_PASS=TRUE" in result.stdout
    assert not dropin.exists()
    assert not dropin_dir.exists()


def test_post_install_verification_failure_reports_rollback_failure_without_false_success(tmp_path):
    result, dropin, _ = _fixture(tmp_path, mutate_after_reload=True)

    assert result.returncode != 0
    assert "VM1_CAPTURE_DROPIN_ROLLBACK_PASS=FALSE" in result.stderr
    assert "VM1_CAPTURE_DROPIN_INSTALL_PASS=TRUE" not in result.stdout
    assert not dropin.exists()

def test_automatic_rollback_preserves_unexpected_dropin_replacement(tmp_path):
    result, dropin, _ = _fixture(tmp_path, replace_after_reload=True)

    assert result.returncode != 0
    assert dropin.exists()
    assert dropin.read_text(encoding="utf-8") == "unexpected replacement\n"
    assert "VM1_CAPTURE_DROPIN_ROLLBACK_PASS=FALSE" in result.stderr


def test_unexpected_replacement_is_preserved_during_rollback(tmp_path):
    replacement = "unexpected replacement\n"
    result, dropin, _ = _fixture(tmp_path, action="rollback", dropin_content=replacement)

    assert result.returncode != 0
    assert dropin.read_text(encoding="utf-8") == replacement
    assert "VM1_CAPTURE_DROPIN_ROLLBACK_PASS=FALSE" in result.stderr


def test_preexisting_dropin_directory_is_preserved_during_install(tmp_path):
    result, _, dropin_dir = _fixture(tmp_path, preexisting_dropin_dir=True)
    original_mode = dropin_dir.stat().st_mode & 0o777

    assert result.returncode == 0, result.stderr + result.stdout
    assert dropin_dir.exists()
    assert (dropin_dir.stat().st_mode & 0o777) == original_mode


def test_rollback_succeeds_when_release_is_unavailable_and_working_directory_is_original(tmp_path):
    result, dropin, _ = _fixture(
        tmp_path,
        action="rollback",
        release=False,
        initial_wd=ORIGINAL_WD,
        dropin_content=f"[Service]\nWorkingDirectory={tmp_path / 'release'}\n",
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "VM1_CAPTURE_DROPIN_ROLLBACK_PASS=TRUE" in result.stdout
    assert not dropin.exists()
def test_rollback_succeeds_when_effective_working_directory_is_still_original(tmp_path):
    result, dropin, _ = _fixture(
        tmp_path,
        action="rollback",
        initial_wd=ORIGINAL_WD,
        dropin_content=f"[Service]\nWorkingDirectory={tmp_path / 'release'}\n",
    )

    assert result.returncode == 0, result.stderr + result.stdout
    assert "VM1_CAPTURE_DROPIN_ROLLBACK_PASS=TRUE" in result.stdout
    assert not dropin.exists()
