from pathlib import Path
import shutil
import subprocess
import sys

import pytest


ROOT = Path(__file__).parents[1]


def test_vm1_inspector_uses_service_identifiers_and_disables_bytecode():
    source = (ROOT / "scripts/g4_inspect_vm1_capture.ps1").read_text(encoding="utf-8")
    assert 'systemctl cat "$SERVICE"' in source
    assert 'systemctl show --all "$SERVICE"' in source
    assert 'published_release_hashes_pass=TRUE' in source
    assert 'PYTHONDONTWRITEBYTECODE=1' in source
    assert 'systemctl cat "$UNIT"' not in source
    assert 'systemctl show "$UNIT"' not in source


def test_vm1_release_preparation_checks_same_filesystem_before_publish():
    source = (ROOT / "scripts/g4_prepare_vm1_release.ps1").read_text(encoding="utf-8")
    assert 'mkdir -m 700 "$STAGE"' in source
    assert 'stage_device=$(stat -c \'%d\' "$STAGE")' in source
    assert 'test "$stage_device" = "$releases_device"' in source
    assert 'mv -- "$EXTRACTED" "$RELEASE"' in source
    assert source.index('test "$stage_device" = "$releases_device"') < source.index('mv -- "$EXTRACTED" "$RELEASE"')


def test_vm1_dropin_workflow_is_guarded_and_only_retargets_working_directory():
    source = (ROOT / "scripts/g4_retarget_vm1_capture_dropin.ps1").read_text(encoding="utf-8")
    assert "[switch]$Install" in source and "[switch]$Rollback" in source
    assert "if (-not $Execute)" in source
    assert "ssh -tt" in source
    assert "sudo -v" in source and "base64 -d | bash -s --" in source
    assert "sudo -n bash -s" not in source
    assert 'WorkingDirectory=$RELEASE' in source
    assert "systemctl daemon-reload" in source
    assert "VM1_CAPTURE_DROPIN_ROLLBACK_PASS=TRUE" in source
    for checkpoint in (
        "remote_checkpoint preflight-unit-identity",
        "remote_checkpoint preflight-service-state",
        "remote_checkpoint preflight-security-properties",
        "remote_checkpoint install-scope-preflight",
        "remote_checkpoint install-release-preflight",
        "remote_checkpoint install-dropin-write",
        "remote_checkpoint install-daemon-reload",
        "remote_checkpoint install-post-verification",
        "VM1_REMOTE_FAILURE_CHECKPOINT=",
    ):
        assert checkpoint in source
    for forbidden in ("systemctl start", "systemctl restart", "systemctl enable", "systemctl stop"):
        assert forbidden not in source


def test_vm1_dropin_validates_release_as_service_user_before_privileged_file_operations():
    source = (ROOT / "scripts/g4_retarget_vm1_capture_dropin.ps1").read_text(encoding="utf-8")

    assert "base64 -d | bash -s --" in source
    assert "sudo -n bash -s" not in source
    assert "sudo -n install" in source
    assert "sudo -n systemctl daemon-reload" in source
    assert source.index("import backend.pcap_capture as capture") < source.index("sudo -n install")


def test_vm1_dropin_install_has_creation_tracking_exact_validation_and_failure_rollback():
    source = (ROOT / "scripts/g4_retarget_vm1_capture_dropin.ps1").read_text(encoding="utf-8")

    assert "dropin_created=0" in source
    assert "dropin_dir_created=0" in source
    assert "trap rollback_install EXIT" in source
    assert "VM1_CAPTURE_DROPIN_ROLLBACK_PASS=TRUE" in source
    assert "VM1_CAPTURE_DROPIN_ROLLBACK_PASS=FALSE" in source
    assert "EXPECTED_DROPIN" in source
    assert "stat -c '%U:%G %a' \"$DROPIN\"" in source
    assert 'if [ "$ACTION" = install ]; then' in source
    assert source.index('if [ "$ACTION" = install ]; then') < source.index('test -d "$RELEASE"')


def test_vm1_owner_controller_uses_prepare_repository_root_and_requires_all_readiness_markers():
    source = (ROOT / "scripts/g4_vm1_owner_controller.ps1").read_text(encoding="utf-8")

    assert "[Parameter(Mandatory=$true)]" in source
    assert "[ValidatePattern('^[0-9a-fA-F]{40}$')]" in source
    assert "$ApprovedHead" in source
    assert "0878d2f774c96eeb638ba6bd2ad28b15deab2cf2" not in source
    assert "-RepositoryRoot $RepositoryRoot" in source
    assert "$Prepare -Vm1Target $Vm1Target" not in source
    assert "-replace \"`r`n?\", \"`n\"" in source
    assert "VM1_RELEASE_APPROVE=YES" in source
    assert "VM1_CAPTURE_DROPIN_INSTALL_APPROVE=YES" in source
    assert "Invoke-OwnerVisibleCommand -Name 'VM1 retarget'" in source
    assert "VM1_RETARGET_AUTHENTICATION=INTERACTIVE_SSH_TTY" in source
    assert "VM1_RETARGET_EXIT_CODE=" in source
    assert "VM1_RETARGET_INVOCATION_ERROR=TRUE" in source
    retarget_source = (ROOT / "scripts/g4_retarget_vm1_capture_dropin.ps1").read_text(encoding="utf-8")
    assert "ssh -tt" in retarget_source
    assert "sudo -v" in retarget_source
    for marker in (
        "VM1_RELEASE_PASS=TRUE",
        "VM1_CAPTURE_DROPIN_INSTALL_PASS=TRUE",
        "VM1_EFFECTIVE_MODULE_PASS=TRUE",
        "VM1_SECURITY_PROPERTIES_UNCHANGED=TRUE",
        "VM1_READY_FOR_G4=TRUE",
    ):
        assert marker in source
    assert "VM1_READY_FOR_G4=TRUE" in source
    assert source.index("VM1_EFFECTIVE_MODULE_PASS=TRUE") < source.index("VM1_READY_FOR_G4=TRUE")


def test_vm1_owner_controller_supports_resume_retarget_only_without_republication():
    source = (ROOT / "scripts/g4_vm1_owner_controller.ps1").read_text(encoding="utf-8")

    assert "[switch]$ResumeRetargetOnly" in source
    assert "Resume-retarget-only mode: VM1 release publication is skipped." in source
    assert "published_release_hashes_pass" in source
    assert "published_capture_sha256" in source
    assert "published_handoff_sha256" in source


def test_controller_reads_empty_pre_post_fields_from_actual_inspection_output():
    powershell = shutil.which("powershell")
    if powershell is None:
        pytest.skip("Windows PowerShell 5.1 is unavailable")

    source = (ROOT / "scripts/g4_vm1_owner_controller.ps1").read_text(encoding="utf-8")
    start = source.index("function Get-ReportField")
    end = source.index("function Require-Marker")
    parser = source[start:end]
    command = parser + "\n" + r'''
$inspection = @(
    'ExecStart=/usr/bin/python3 -m backend.pcap_capture',
    'ExecStartPre=',
    'ExecStartPost=',
    'User=tanhv'
)
$pre = [string](Get-ReportField -Lines $inspection -Name 'ExecStartPre')
$post = [string](Get-ReportField -Lines $inspection -Name 'ExecStartPost')
if ($pre -ne '' -or $post -ne '') { exit 1 }
Write-Output 'EMPTY_OPTIONAL_FIELDS_PASS=TRUE'
'''
    result = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "EMPTY_OPTIONAL_FIELDS_PASS=TRUE" in result.stdout


@pytest.mark.parametrize("line_ending", ["crlf", "lf"])
def test_retarget_runtime_normalizes_payload_for_install_and_rollback(tmp_path, line_ending):
    engines = [
        engine for name in ("powershell", "pwsh")
        if (engine := shutil.which(name)) is not None
    ]
    if not engines:
        pytest.skip("PowerShell 5.1 and PowerShell 7 are unavailable")

    source = (ROOT / "scripts/g4_retarget_vm1_capture_dropin.ps1").read_text(
        encoding="utf-8"
    )
    normalized_source = source.replace("\r\n", "\n").replace("\r", "\n")
    newline = "\r\n" if line_ending == "crlf" else "\n"
    script_path = tmp_path / f"g4-retarget-{line_ending}.ps1"
    script_path.write_bytes(normalized_source.replace("\n", newline).encode("utf-8"))

    for engine in engines:
        for action, switch_name in (("install", "Install"), ("rollback", "Rollback")):
            command = (
                "$ErrorActionPreference = 'Stop'\n"
                "$global:DecodedPayload = $null\n"
                "function global:ssh {\n"
                "  $argumentList = @($args)\n"
                "  $command = [string]$argumentList[$argumentList.Count - 1]\n"
                "  $match = [regex]::Match($command, \"printf %s '([^']+)' \\| base64 -d \\| bash -s --\")\n"
                "  if (-not $match.Success) { throw 'mock SSH did not receive the encoded Bash payload' }\n"
                "  $global:DecodedPayload = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($match.Groups[1].Value))\n"
                "  if ($global:DecodedPayload.Contains([char]13)) { throw 'payload retained CR characters' }\n"
                f"  if (-not $global:DecodedPayload.Contains(\"ACTION='{action}'\")) {{ throw 'wrong action in payload' }}\n"
                "  if ($command -notmatch 'sudo -v') { throw 'interactive sudo authentication was not requested' }\n"
                "  $global:LASTEXITCODE = 0\n"
                "}\n"
                f"& '{str(script_path).replace(chr(39), chr(39) * 2)}' -{switch_name} "
                "-Execute -Vm1Target 'mock@vm1'\n"
                "if ($null -eq $global:DecodedPayload) { throw 'mock SSH was not invoked' }\n"
            )
            result = subprocess.run(
                [engine, "-NoProfile", "-NonInteractive", "-Command", command],
                capture_output=True,
                text=True,
            )
            assert result.returncode == 0, (
                f"{engine} {action} {line_ending} failed:\n"
                f"stdout={result.stdout}\nstderr={result.stderr}"
            )
            assert "sudo -v" in command


def test_owner_controller_preserves_native_output_on_success_and_failure():
    engines = [
        engine for name in ("powershell", "pwsh")
        if (engine := shutil.which(name)) is not None
    ]
    if not engines:
        pytest.skip("PowerShell 5.1 and PowerShell 7 are unavailable")

    source = (ROOT / "scripts/g4_vm1_owner_controller.ps1").read_text(encoding="utf-8")
    start = source.index("function Invoke-OwnerVisibleCommand")
    end = source.index("function Show-Output")
    helper = source[start:end]
    native = str(Path(sys.executable)).replace("'", "''")
    command = helper + r'''
$success = Invoke-OwnerVisibleCommand -Name 'native-success' -Command {
    & '__PYTHON__' -c "import sys; print('NATIVE_SUCCESS_STDOUT'); print('NATIVE_SUCCESS_STDERR', file=sys.stderr); sys.exit(0)"
}
$failure = Invoke-OwnerVisibleCommand -Name 'native-failure' -Command {
    & '__PYTHON__' -c "import sys; print('NATIVE_FAILURE_STDOUT'); print('NATIVE_FAILURE_STDERR', file=sys.stderr); sys.exit(7)"
}
$throwing = Invoke-OwnerVisibleCommand -Name 'terminating-child' -Command {
    Write-Output 'BEFORE_TERMINATING_CHILD_ERROR'
    throw 'TERMINATING_CHILD_ERROR'
}
$all = (($success.Output + $failure.Output + $throwing.Output) -join "`n")
if ($success.ExitCode -ne 0) { exit 1 }
if ($failure.ExitCode -ne 7) { exit 2 }
foreach ($text in @('NATIVE_SUCCESS_STDOUT', 'NATIVE_SUCCESS_STDERR', 'NATIVE_FAILURE_STDOUT', 'NATIVE_FAILURE_STDERR', 'BEFORE_TERMINATING_CHILD_ERROR')) {
    if ($all -notlike "*$text*") { exit 3 }
}
if ($success.Error -ne $null -or $failure.Error -ne $null -or $throwing.Error -eq $null) { exit 4 }
Write-Output 'NATIVE_OUTPUT_PRESERVATION_PASS=TRUE'
'''
    command = command.replace('__PYTHON__', native)

    for engine in engines:
        result = subprocess.run(
            [engine, "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"{engine}:\nstdout={result.stdout}\nstderr={result.stderr}"
        assert "NATIVE_OUTPUT_PRESERVATION_PASS=TRUE" in result.stdout
        assert "[native-success]" in result.stdout
        assert "[native-failure]" in result.stdout
