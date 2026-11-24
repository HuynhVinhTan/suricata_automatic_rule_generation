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
    assert "sudo -v" in source and "sudo -n bash -s" in source
    assert "WorkingDirectory=__RELEASE__" in source
    assert "systemctl daemon-reload" in source
    assert "VM1_CAPTURE_DROPIN_ROLLBACK_PASS=TRUE" in source
    for forbidden in ("systemctl start", "systemctl restart", "systemctl enable", "systemctl stop"):
        assert forbidden not in source
