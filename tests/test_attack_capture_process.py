"""Process-level orchestration tests with mocked owner/VM2 commands."""

import os
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import subprocess

import pytest

from scripts.test_attack_fixtures import write_complete_attack_fixture


pytestmark = pytest.mark.skipif(os.name == "nt", reason="requires POSIX process groups")
SCRIPT = Path(__file__).parents[1] / "scripts" / "demo" / "vm2-capture-session.sh"
SUPERVISOR = Path(__file__).parents[1] / "scripts" / "demo" / "vm2-capture-supervisor.py"


def _write_executable(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)


def _write_test_copy(path: Path, supervisor_copy: Path) -> None:
    """Create a deterministic test copy; production script has no test bypass."""
    text = SCRIPT.read_text(encoding="utf-8")
    text = text.replace("MAX_SECONDS=120\n", "MAX_SECONDS=5\n", 1)
    text = text.replace(
        "SUPERVISOR=/usr/local/libexec/suricata-ai-showcase/vm2-capture-supervisor",
        f'SUPERVISOR="{supervisor_copy.as_posix()}"',
        1,
    )
    text = text.replace("if [[ ! -t 0 || ! -t 1 ]]; then", "if false; then", 1)
    text = text.replace("if [[ ${EUID:-$(id -u)} -eq 0 ]]; then", "if false; then", 1)
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)


@pytest.fixture
def mocked_capture(tmp_path):
    root = tmp_path / "showcase"
    (root / "current/scripts/demo").mkdir(parents=True)
    (root / "evidence").mkdir(mode=0o700)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fixture_pcap, fixture_manifest = write_complete_attack_fixture(tmp_path / "fixture")
    test_script = tmp_path / "vm2-capture-session-test-copy.sh"
    supervisor_copy = tmp_path / "vm2-capture-supervisor-test-copy.py"
    supervisor_text = SUPERVISOR.read_text(encoding="utf-8")
    supervisor_text = supervisor_text.replace(
        'EVIDENCE_ROOT = Path("/home/kali/suricata-ai-showcase/evidence")',
        f"EVIDENCE_ROOT = Path({str(root / 'evidence').__repr__()})",
        1,
    )
    supervisor_text = supervisor_text.replace(
        'INSTALL_PATH = Path("/usr/local/libexec/suricata-ai-showcase/vm2-capture-supervisor")',
        f"INSTALL_PATH = Path({str(supervisor_copy).__repr__()})",
        1,
    )
    supervisor_text = supervisor_text.replace(
        "INSTALLATION_OWNER_UID = 0",
        "INSTALLATION_OWNER_UID = os.geteuid()",
        1,
    )
    supervisor_text = supervisor_text.replace(
        "INSTALLATION_VALIDATION_BOUNDARY: Path | None = None",
        f"INSTALLATION_VALIDATION_BOUNDARY = Path({str(tmp_path).__repr__()})",
        1,
    )
    supervisor_text = supervisor_text.replace(
        'TCPDUMP = "/usr/bin/tcpdump"',
        f"TCPDUMP = {str(bin_dir / 'tcpdump').__repr__()}",
        1,
    )
    supervisor_text = supervisor_text.replace(
        'env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},',
        'env=dict(os.environ, PATH="/usr/bin:/bin", LC_ALL="C"),',
        1,
    )
    supervisor_copy.write_text(supervisor_text, encoding="utf-8")
    supervisor_copy.chmod(0o755)
    timeout_supervisor_copy = tmp_path / "vm2-capture-supervisor-timeout-test-copy.py"
    timeout_supervisor_text = supervisor_text.replace("MAX_SECONDS = 120", "MAX_SECONDS = 1", 1).replace(
        f"INSTALL_PATH = Path({str(supervisor_copy).__repr__()})",
        f"INSTALL_PATH = Path({str(timeout_supervisor_copy).__repr__()})",
        1,
    )
    timeout_supervisor_copy.write_text(timeout_supervisor_text, encoding="utf-8")
    timeout_supervisor_copy.chmod(0o755)
    _write_test_copy(test_script, supervisor_copy)
    timeout_script = tmp_path / "vm2-capture-session-timeout-test-copy.sh"
    timeout_script.write_text(
        test_script.read_text(encoding="utf-8")
        .replace(f'SUPERVISOR="{supervisor_copy.as_posix()}"', f'SUPERVISOR="{timeout_supervisor_copy.as_posix()}"', 1)
        .replace("MAX_SECONDS=5\n", "MAX_SECONDS=1\n", 1),
        encoding="utf-8",
    )
    timeout_script.chmod(0o755)
    (root / "fixture.pcap").write_bytes(fixture_pcap.read_bytes())
    (root / "fixture.json").write_text(fixture_manifest.read_text(encoding="utf-8"), encoding="utf-8")
    (root / "current/scripts/verify_attack_evidence.py").write_bytes(
        (Path(__file__).parents[1] / "scripts/verify_attack_evidence.py").read_bytes()
    )
    marker = tmp_path / "tcpdump.pid"
    auth_log = tmp_path / "sudo-auth.log"
    sudo_log = tmp_path / "sudo.log"
    _write_executable(bin_dir / "ip", "#!/usr/bin/env python3\nprint('2: eth1 inet 192.168.10.20/24')\n")
    _write_executable(bin_dir / "sudo", """#!/usr/bin/env python3
import os, sys
if os.environ.get('FAKE_SUDO_LOG'):
    open(os.environ['FAKE_SUDO_LOG'], 'a', encoding='utf-8').write(' '.join(sys.argv[1:]) + '\\n')
if sys.argv[1] == '-v':
    open(os.environ['FAKE_AUTH_LOG'], 'a', encoding='utf-8').write('auth\\n')
    raise SystemExit(int(os.environ.get('FAKE_SUDO_STATUS', '0')))
args = sys.argv[1:]
is_supervisor = any('vm2-capture-supervisor' in item for item in args)
if args and args[0] == '-n' and os.environ.get('FAKE_SUDO_TERMINAL_SCOPED') == '1' and not is_supervisor:
    sys.stderr.write('sudo: a password is required\\n')
    raise SystemExit(1)
if os.environ.get('FAKE_UNPRIVILEGED_SIGNAL_EPERM') == '1' and not is_supervisor:
    sys.stderr.write('kill: Operation not permitted\\n')
    raise SystemExit(1)
if args and args[0] == '-n': args = args[1:]
if os.environ.get('FAKE_SUDO_TERMINAL_SCOPED') == '1' and not os.path.exists(os.environ['FAKE_AUTH_LOG']):
    sys.stderr.write('sudo: a password is required\\n')
    raise SystemExit(1)
if is_supervisor and os.environ.get('FAKE_UNPRIVILEGED_SIGNAL_EPERM') == '1':
    open(os.environ['FAKE_PRIVILEGED_SUPERVISOR_MARKER'], 'w', encoding='utf-8').write('privileged-supervisor\\n')
    os.environ['FAKE_PRIVILEGED_SUPERVISOR'] = '1'
os.execvpe(args[0], args, os.environ)
""")
    _write_executable(bin_dir / "tcpdump", """#!/usr/bin/env python3
import os, signal, sys, time
args = sys.argv[1:]
out = args[args.index('-w') + 1]
open(os.environ['FAKE_TCPDUMP_PID'], 'w', encoding='utf-8').write(str(os.getpid()))
if os.environ.get('FAKE_CHILD_MARKER'):
    open(os.environ['FAKE_CHILD_MARKER'], 'w', encoding='utf-8').write(str(os.getpid()))
if os.environ.get('FAKE_TCPDUMP_READY', '1') == '1':
    open(out, 'wb').write(open(os.environ['FAKE_PCAP'], 'rb').read())
    sys.stderr.write('listening on eth1, link-type EN10MB\\n48 packets captured\\n48 packets received by filter\\n0 packets dropped by kernel\\n')
    sys.stderr.flush()
def stop(_signum, _frame): raise SystemExit(0)
signal.signal(signal.SIGINT, stop)
signal.signal(signal.SIGTERM, stop)
while True: time.sleep(1)
""")
    _write_executable(root / "current/scripts/demo/vm2-generate-attack.sh", """#!/usr/bin/env python3
import os, shutil, sys, time
time.sleep(float(os.environ.get('FAKE_GENERATOR_SLEEP', '1.6')))
shutil.copyfile(os.environ['FAKE_MANIFEST'], sys.argv[1])
raise SystemExit(int(os.environ.get('FAKE_GENERATOR_STATUS', '0')))
""")
    return {"root": root, "bin": bin_dir, "fixture_dir": tmp_path / "fixture", "pcap": root / "fixture.pcap", "pid": marker, "auth": auth_log, "sudo_log": sudo_log, "script": test_script, "timeout_script": timeout_script, "supervisor": supervisor_copy}


def _run(fixture, name="attack-20261123T000000Z.pcap", **extra):
    script = extra.pop("script", fixture["script"])
    # Rebase only an intact synthetic fixture immediately before launch. This
    # keeps strict capture/manifest windows around the mocked process runtime;
    # deliberately malformed PCAP tests remain untouched.
    if fixture["pcap"].read_bytes()[:4] == b"\xd4\xc3\xb2\xa1":
        fresh_pcap, fresh_manifest = write_complete_attack_fixture(
            fixture["fixture_dir"], base=datetime.now(timezone.utc) + timedelta(seconds=1)
        )
        fixture["pcap"].write_bytes(fresh_pcap.read_bytes())
        (fixture["root"] / "fixture.json").write_text(fresh_manifest.read_text(encoding="utf-8"), encoding="utf-8")
    out = fixture["root"] / "evidence" / name
    manifest = fixture["root"] / "evidence" / "attack.json"
    env = os.environ.copy()
    env.update({
        "PATH": str(fixture["bin"]) + os.pathsep + env.get("PATH", ""),
        "SHOWCASE_ROOT": str(fixture["root"]), "CAPTURE_TEST_MODE": "1",
        "FAKE_PCAP": str(fixture["pcap"]), "FAKE_MANIFEST": str(fixture["root"] / "fixture.json"),
        "FAKE_TCPDUMP_PID": str(fixture["pid"]), "FAKE_AUTH_LOG": str(fixture["auth"]),
        "FAKE_SUDO_LOG": str(fixture["sudo_log"]),
        "READINESS_WAIT_ITERATIONS": "2",
    })
    env.update(extra)
    return subprocess.run(["bash", str(script), str(out), str(manifest)], cwd=fixture["root"], env=env, capture_output=True, text=True, timeout=20), out


def test_success_authenticates_in_foreground_and_cleans_capture_process(mocked_capture):
    result, out = _run(mocked_capture)
    assert result.returncode == 0, result.stderr
    assert "ATTACK_CAPTURE_READY" in result.stdout
    assert out.is_file()
    assert not Path(str(out) + ".partial.pcap").exists()
    assert mocked_capture["auth"].read_text(encoding="utf-8").splitlines() == ["auth"]
    assert not _pid_exists(mocked_capture["pid"])


def test_fixture_capture_window_has_setup_slack_for_strict_metadata_ordering(mocked_capture):
    manifest = json.loads((mocked_capture["root"] / "fixture.json").read_text(encoding="utf-8"))
    started = datetime.fromisoformat(manifest["started_at_utc"].replace("Z", "+00:00"))
    assert (started - datetime.now(timezone.utc)).total_seconds() >= 20


def test_success_reaps_tcpdump_child_process(mocked_capture):
    child_marker = mocked_capture["root"] / "tcpdump-child.pid"
    (mocked_capture["bin"] / "sudo").write_text("""#!/usr/bin/env python3
import os, subprocess, sys
if sys.argv[1] == '-v':
    open(os.environ['FAKE_AUTH_LOG'], 'a', encoding='utf-8').write('auth\\n')
    raise SystemExit(0)
args = sys.argv[1:]
if args and args[0] == '-n': args = args[1:]
child = subprocess.Popen(args, env=dict(os.environ, FAKE_CHILD_MARKER=os.environ['FAKE_CHILD_MARKER']))
child.wait()
raise SystemExit(child.returncode)
""", encoding="utf-8")
    mocked_capture["child"] = child_marker
    result, _ = _run(mocked_capture, FAKE_CHILD_MARKER=str(child_marker))
    assert result.returncode == 0, result.stderr
    assert child_marker.exists()
    assert not _pid_exists(child_marker)


def test_terminal_scoped_sudo_authentication_is_reused_before_process_group(mocked_capture):
    result, out = _run(mocked_capture, FAKE_SUDO_TERMINAL_SCOPED="1")

    assert result.returncode == 0, result.stderr
    assert out.is_file()
    sudo_invocations = mocked_capture["sudo_log"].read_text(encoding="utf-8").splitlines()
    assert sudo_invocations[0] == "-v"
    assert all("-n tcpdump" not in invocation for invocation in sudo_invocations)


def test_auth_failure_never_starts_tcpdump(mocked_capture):
    result, out = _run(mocked_capture, FAKE_SUDO_STATUS="1")
    assert result.returncode == 77
    assert "authentication failed" in result.stderr
    assert not out.exists() and not mocked_capture["pid"].exists()


def test_readiness_failure_preserves_log_and_has_no_orphan(mocked_capture):
    result, out = _run(mocked_capture, FAKE_TCPDUMP_READY="0")
    assert result.returncode == 77
    assert "readiness" in result.stderr.lower()
    assert not out.exists() and Path(str(out) + ".tcpdump.log").exists()
    assert not _pid_exists(mocked_capture["pid"])


def test_generator_error_preserves_partial_and_kills_capture(mocked_capture):
    result, out = _run(mocked_capture, FAKE_GENERATOR_STATUS="7")
    assert result.returncode == 1
    assert "CAPTURE_PARTIAL" in result.stderr
    assert not out.exists() and Path(str(out) + ".partial.pcap").exists()
    assert not _pid_exists(mocked_capture["pid"])


def test_privileged_supervisor_owns_cleanup_when_parent_signals_would_be_eperm(mocked_capture):
    boundary_marker = mocked_capture["root"] / "privileged-supervisor.marker"
    result, out = _run(
        mocked_capture,
        FAKE_SUDO_TERMINAL_SCOPED="1",
        FAKE_UNPRIVILEGED_SIGNAL_EPERM="1",
        FAKE_PRIVILEGED_SUPERVISOR_MARKER=str(boundary_marker),
        FAKE_GENERATOR_STATUS="9",
    )
    assert result.returncode == 1
    assert "CAPTURE_PARTIAL" in result.stderr
    assert Path(str(out) + ".partial.pcap").exists()
    assert not _pid_exists(mocked_capture["pid"])
    assert boundary_marker.read_text(encoding="utf-8").strip() == "privileged-supervisor"
    parent = SCRIPT.read_text(encoding="utf-8")
    assert re.search(r"(?m)^\s*(?:command\s+)?kill\b", parent) is None
    assert "-n" in mocked_capture["sudo_log"].read_text(encoding="utf-8")


def test_timeout_preserves_partial_and_kills_capture(mocked_capture):
    result, out = _run(mocked_capture, script=mocked_capture["timeout_script"], CAPTURE_TEST_MAX_SECONDS="120", FAKE_GENERATOR_SLEEP="3")
    assert result.returncode == 1
    assert "CAPTURE_PARTIAL" in result.stderr
    assert not out.exists() and not _pid_exists(mocked_capture["pid"])


def test_validation_failure_preserves_partial_and_does_not_print_ready(mocked_capture):
    mocked_capture["pcap"].write_bytes(b"not-a-pcap")
    result, out = _run(mocked_capture)
    assert result.returncode == 1
    assert "verification failed" in result.stderr
    assert "ATTACK_CAPTURE_READY" not in result.stdout
    assert not out.exists() and Path(str(out) + ".verification.json").exists()


def test_overwrite_refusal_happens_before_authentication(mocked_capture):
    out = mocked_capture["root"] / "evidence" / "attack-20261123T000000Z.pcap"
    out.write_bytes(b"existing")
    result, _ = _run(mocked_capture)
    assert result.returncode == 77
    assert "overwrite" in result.stderr.lower() and not mocked_capture["auth"].exists()


def test_non_tty_instructions_are_explicit(mocked_capture):
    env = os.environ.copy()
    env.update({"SHOWCASE_ROOT": str(mocked_capture["root"]), "PATH": str(mocked_capture["bin"]) + os.pathsep + env.get("PATH", "")})
    result = subprocess.run(["bash", str(SCRIPT)], env=env, capture_output=True, text=True, timeout=5)
    assert result.returncode == 77
    assert "ssh -tt suricata-vm2" in result.stderr


def test_environment_overrides_cannot_bypass_production_guards(mocked_capture):
    text = SCRIPT.read_text(encoding="utf-8")
    assert "CAPTURE_TEST_MODE" not in text
    assert "CAPTURE_TEST_MAX_SECONDS" not in text
    env = os.environ.copy()
    env.update({
        "PATH": str(mocked_capture["bin"]) + os.pathsep + env.get("PATH", ""),
        "SHOWCASE_ROOT": str(mocked_capture["root"]),
        "CAPTURE_TEST_MODE": "1",
        "CAPTURE_TEST_MAX_SECONDS": "1",
    })
    result = subprocess.run(["bash", str(SCRIPT)], env=env, capture_output=True, text=True, timeout=5)
    assert result.returncode == 77
    assert "ssh -tt suricata-vm2" in result.stderr


def _pid_exists(path: Path) -> bool:
    if not path.exists(): return False
    try: os.kill(int(path.read_text(encoding="utf-8")), 0)
    except ProcessLookupError: return False
    return True
