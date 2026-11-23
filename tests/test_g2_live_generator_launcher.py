"""Offline regression tests for the bounded G2 generator launcher."""

from __future__ import annotations

import shlex
import subprocess

import pytest

from scripts import g2_live_generator_launcher as launcher


FAILED_RUN_ID = "g2-live-attack-20261123T051225Z-29e0e0f0da9147ee"
FAILED_SEED = 20261123051225


# Exact expanded remote script from the failed PowerShell wrapper.  In a
# double-quoted PowerShell here-string, backslash does not escape '$', so the
# Bash quote opened by mkdir remains open across the following exec line.
FAILED_REMOTE_SCRIPT = """set -eu
umask 077
run_id='g2-live-attack-20261123T051225Z-29e0e0f0da9147ee'
out_dir="/home/kali/suricata-ai-showcase/evidence/live/"
mkdir -p "\\"
exec /usr/bin/python3 /home/kali/suricata-ai-showcase/releases/a8fe3e82e701beafc9e47fb7bc5b45064029f8be/scripts/lab_slow_port_scan.py --run-id "\\" --target 192.168.10.10 --source-ip 192.168.10.20 --ports '18100,18101,18102,18103,18104,18105,18106,18107,18108,18109,18110,18111,18112,18113,18114,18115,18116,18117,18118,18119,18120,18121,18122,18123' --interval 2.0 --timeout 1.0 --seed 20261123051225 --out "\\/generator.json"
"""


def test_exact_failed_wrapper_passes_generator_flags_to_mkdir():
    """Reproduce the observed mkdir --target failure without any network call."""
    tokens = shlex.split(FAILED_REMOTE_SCRIPT, posix=True)
    mkdir_index = tokens.index("mkdir")
    args = tokens[mkdir_index + 1 :]
    assert "--target" in args
    assert "--source-ip" in args
    assert "--seed" in args


def test_corrected_script_has_separate_mkdir_and_generator_arguments():
    request = launcher.G2GeneratorRequest(
        run_id="g2-live-attack-20261123T060000Z-0123456789abcdef",
        seed=20261123060000,
        output_dir="/home/kali/suricata-ai-showcase/evidence/live/g2-live-attack-20261123T060000Z-0123456789abcdef",
    )
    script = launcher.build_remote_generator_script(request)
    assert "mkdir -p -- \"$out_dir\"" in script
    assert "--target 192.168.10.10" in script
    assert "--source-ip 192.168.10.20" in script
    assert "--ports 18100,18101,18102,18103,18104,18105,18106,18107,18108,18109,18110,18111,18112,18113,18114,18115,18116,18117,18118,18119,18120,18121,18122,18123" in script
    assert "mkdir -p -- \"$out_dir\"\nexec " in script
    assert script.count("exec /usr/bin/python3") == 1
    assert "--retry" not in script


def test_corrected_script_has_balanced_shell_lines_and_quotes_paths():
    request = launcher.G2GeneratorRequest(
        run_id="g2-live-attack-20261123T060001Z-0123456789abcdef",
        seed=20261123060001,
        output_dir="/home/kali/suricata-ai-showcase/evidence/live/g2-live-attack-20261123T060001Z-0123456789abcdef",
    )
    script = launcher.build_remote_generator_script(request)
    # The Windows host has no usable local Bash runtime in this environment;
    # validate every generated command line with the POSIX quoting lexer.
    for line in script.splitlines():
        if line:
            shlex.split(line, posix=True)
    assert "out_dir=/home/kali/suricata-ai-showcase/evidence/live/g2-live-attack-20261123T060001Z-0123456789abcdef" in script
    assert "--out \"$out_dir/generator.json\"" in script


def test_ssh_argv_has_one_remote_script_and_no_retry():
    request = launcher.G2GeneratorRequest(
        run_id="g2-live-attack-20261123T060002Z-0123456789abcdef",
        seed=20261123060002,
        output_dir="/home/kali/suricata-ai-showcase/evidence/live/g2-live-attack-20261123T060002Z-0123456789abcdef",
    )
    argv = launcher.build_ssh_argv(request)
    assert argv[:2] == ["ssh", "-o"]
    assert argv[-2] == "kali@192.168.10.20"
    assert argv[-1] == launcher.build_remote_generator_script(request)
    assert argv.count("--target") == 0


def test_runner_invokes_ssh_once_and_propagates_failure():
    request = launcher.G2GeneratorRequest(
        run_id="g2-live-attack-20261123T060004Z-0123456789abcdef",
        seed=20261123060004,
        output_dir="/home/kali/suricata-ai-showcase/evidence/live/g2-live-attack-20261123T060004Z-0123456789abcdef",
    )
    calls = []

    def fail_once(argv, **kwargs):
        calls.append((argv, kwargs))
        raise subprocess.CalledProcessError(1, argv)

    with pytest.raises(subprocess.CalledProcessError):
        launcher.run_generator_once(request, runner=fail_once)
    assert len(calls) == 1
    assert calls[0][1]["check"] is True
    assert calls[0][1]["timeout"] == 180


def test_request_rejects_shell_sensitive_or_duplicate_run_ids():
    with pytest.raises(ValueError):
        launcher.G2GeneratorRequest(
            run_id="bad; touch /tmp/x",
            seed=1,
            output_dir="/home/kali/evidence/run",
        )
    with pytest.raises(ValueError):
        launcher.G2GeneratorRequest(
            run_id="g2-live-attack-20261123T060003Z-0123456789abcdef",
            seed=1,
            output_dir="/home/kali/evidence/run/../escape",
        )
