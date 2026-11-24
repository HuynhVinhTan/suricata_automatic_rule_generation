from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_vm1_inspector_uses_service_identifiers_and_disables_bytecode():
    source = (ROOT / "scripts/g4_inspect_vm1_capture.ps1").read_text(encoding="utf-8")
    assert 'systemctl cat "$SERVICE"' in source
    assert 'systemctl show "$SERVICE"' in source
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
    assert "sudo -v" in (source + (ROOT / "scripts/g4_retarget_vm1_capture_dropin.ps1").read_text(encoding="utf-8"))
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
