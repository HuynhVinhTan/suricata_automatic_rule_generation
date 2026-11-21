"""Process-level orchestration tests with mocked owner/VM2 commands."""

import os
from pathlib import Path
import subprocess

import pytest

from scripts.test_attack_fixtures import write_complete_attack_fixture


pytestmark = pytest.mark.skipif(os.name == "nt", reason="requires POSIX process groups")
SCRIPT = Path(__file__).parents[1] / "scripts" / "demo" / "vm2-capture-session.sh"


def _write_executable(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)


@pytest.fixture
def mocked_capture(tmp_path):
    root = tmp_path / "showcase"
    (root / "current/scripts/demo").mkdir(parents=True)
    (root / "evidence").mkdir()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fixture_pcap, fixture_manifest = write_complete_attack_fixture(tmp_path / "fixture")
    (root / "fixture.pcap").write_bytes(fixture_pcap.read_bytes())
    (root / "fixture.json").write_text(fixture_manifest.read_text(encoding="utf-8"), encoding="utf-8")
    (root / "current/scripts/verify_attack_evidence.py").write_bytes(
        (Path(__file__).parents[1] / "scripts/verify_attack_evidence.py").read_bytes()
    )
    marker = tmp_path / "tcpdump.pid"
    auth_log = tmp_path / "sudo-auth.log"
    _write_executable(bin_dir / "ip", "#!/usr/bin/env python3\nprint('2: eth1 inet 192.168.10.20/24')\n")
    _write_executable(bin_dir / "sudo", """#!/usr/bin/env python3
import os, sys
if sys.argv[1] == '-v':
    open(os.environ['FAKE_AUTH_LOG'], 'a', encoding='utf-8').write('auth\\n')
    raise SystemExit(int(os.environ.get('FAKE_SUDO_STATUS', '0')))
args = sys.argv[1:]
if args and args[0] == '-n': args = args[1:]
os.execvp(args[0], args)
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
    return {"root": root, "bin": bin_dir, "pcap": root / "fixture.pcap", "pid": marker, "auth": auth_log}


def _run(fixture, name="attack.pcap", **extra):
    out = fixture["root"] / "evidence" / name
    manifest = fixture["root"] / "evidence" / "attack.json"
    env = os.environ.copy()
    env.update({
        "PATH": str(fixture["bin"]) + os.pathsep + env.get("PATH", ""),
        "SHOWCASE_ROOT": str(fixture["root"]), "CAPTURE_TEST_MODE": "1",
        "FAKE_PCAP": str(fixture["pcap"]), "FAKE_MANIFEST": str(fixture["root"] / "fixture.json"),
        "FAKE_TCPDUMP_PID": str(fixture["pid"]), "FAKE_AUTH_LOG": str(fixture["auth"]),
        "READINESS_WAIT_ITERATIONS": "2",
    })
    env.update(extra)
    return subprocess.run(["bash", str(SCRIPT), str(out), str(manifest)], cwd=fixture["root"], env=env, capture_output=True, text=True, timeout=20), out


def test_success_authenticates_in_foreground_and_cleans_capture_process(mocked_capture):
    result, out = _run(mocked_capture)
    assert result.returncode == 0, result.stderr
    assert "ATTACK_CAPTURE_READY" in result.stdout
    assert out.is_file()
    assert not Path(str(out) + ".partial.pcap").exists()
    assert mocked_capture["auth"].read_text(encoding="utf-8").splitlines() == ["auth"]
    assert not _pid_exists(mocked_capture["pid"])


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


def test_timeout_preserves_partial_and_kills_capture(mocked_capture):
    result, out = _run(mocked_capture, CAPTURE_TEST_MAX_SECONDS="1", FAKE_GENERATOR_SLEEP="3")
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
    out = mocked_capture["root"] / "evidence" / "attack.pcap"
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


def _pid_exists(path: Path) -> bool:
    if not path.exists(): return False
    try: os.kill(int(path.read_text(encoding="utf-8")), 0)
    except ProcessLookupError: return False
    return True
