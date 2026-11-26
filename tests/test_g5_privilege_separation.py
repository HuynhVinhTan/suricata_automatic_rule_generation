import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from netids import privilege_separation as ps
from netids.isolated_suricata_runtime import IsolatedRuntimeError, IsolatedSuricataRuntime


def test_operator_must_have_euid_zero(monkeypatch):
    monkeypatch.setattr(ps.os, "geteuid", lambda: 1000, raising=False)
    with pytest.raises(ps.PrivilegeSeparationError, match="EUID 0"):
        ps.require_root_operator()


def test_service_account_lookup_requires_exact_dedicated_identity(monkeypatch):
    monkeypatch.setattr(ps.pwd, "getpwnam", lambda name: SimpleNamespace(
        pw_name=name, pw_uid=999, pw_gid=982, pw_dir="/nonexistent",
        pw_shell="/usr/sbin/nologin",
    ))
    monkeypatch.setattr(ps.grp, "getgrnam", lambda name: SimpleNamespace(
        gr_name=name, gr_gid=982,
    ))
    account = ps.lookup_service_account()
    assert account.username == "suricata-g5"
    assert account.uid == 999
    assert account.gid == 982


def test_daemon_arguments_drop_only_suricata_child_privileges(tmp_path):
    runtime = object.__new__(IsolatedSuricataRuntime)
    runtime.suricata = "/usr/bin/suricata"
    runtime.config = tmp_path / "suricata.yaml"
    runtime.logdir = tmp_path / "logs"
    runtime.pidfile = tmp_path / "runtime" / "suricata.pid"
    runtime.service_user = "suricata-g5"
    runtime.service_group = "suricata-g5"
    arguments = runtime._daemon_arguments()
    assert "--user=suricata-g5" in arguments
    assert "--group=suricata-g5" in arguments
    assert "sudo" not in arguments


def test_proc_status_requires_all_real_uids_gids_and_rejects_root_supplementary_group():
    status = """Name:\tsuricata\nState:\tS (sleeping)\nUid:\t999\t999\t999\t999\nGid:\t982\t982\t982\t982\nGroups:\t982 0\n"""
    with pytest.raises(ps.PrivilegeSeparationError, match="supplementary root"):
        ps.verify_proc_identity_text(status)


def test_proc_status_accepts_dedicated_identity():
    status = """Name:\tsuricata\nState:\tS (sleeping)\nUid:\t999\t999\t999\t999\nGid:\t982\t982\t982\t982\nGroups:\t982\n"""
    identity = ps.verify_proc_identity_text(status)
    assert identity.uid == 999
    assert identity.gid == 982
    assert identity.groups == (982,)


def test_effective_yaml_references_are_explicit_and_narrow(tmp_path):
    config = tmp_path / "suricata.yaml"
    classification = tmp_path / "classification.config"
    reference = tmp_path / "reference.config"
    classification.write_text("class", encoding="utf-8")
    reference.write_text("reference", encoding="utf-8")
    refs = ps.referenced_configuration_files({
        "classification-file": "classification.config",
        "reference-config-file": "reference.config",
        "rule-files": ["active.rules"],
        "default-rule-path": str(tmp_path),
    }, config)
    assert refs == (classification, reference)


def test_acl_application_uses_argument_arrays_and_no_audit_path(tmp_path):
    calls = []
    paths = ps.AttemptAccessPaths(
        attempt_root=tmp_path / "attempt",
        runtime_dir=tmp_path / "attempt" / "runtime",
        rules_dir=tmp_path / "attempt" / "rules",
        active_rules=tmp_path / "attempt" / "rules" / "active.rules",
        logs_dir=tmp_path / "attempt" / "logs",
        effective_config=tmp_path / "attempt" / "suricata.yaml",
        referenced_files=(tmp_path / "classification.config",),
    )
    paths.active_rules.parent.mkdir(parents=True)
    paths.attempt_root.mkdir(parents=True, exist_ok=True)
    paths.runtime_dir.mkdir()
    paths.logs_dir.mkdir()
    paths.effective_config.write_text("{}", encoding="utf-8")
    paths.active_rules.write_text("baseline", encoding="utf-8")
    paths.referenced_files[0].write_text("classification", encoding="utf-8")

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    ps.apply_attempt_acls(paths, runner=fake_run)
    assert calls
    assert all(call[1]["shell"] is False for call in calls)
    assert all("audit" not in str(call[0]) for call in calls)
    assert any("--x" in token for call in calls for token in call[0])
    assert any("-wx" in token for call in calls for token in call[0])
    assert any("r--" in token for call in calls for token in call[0])


def test_acl_failure_is_fail_closed(tmp_path):
    paths = ps.AttemptAccessPaths(
        attempt_root=tmp_path / "attempt", runtime_dir=tmp_path / "runtime",
        rules_dir=tmp_path / "rules", active_rules=tmp_path / "active.rules",
        logs_dir=tmp_path / "logs", effective_config=tmp_path / "suricata.yaml",
    )
    def failed_run(*args, **kwargs):
        return SimpleNamespace(returncode=1, stdout="", stderr="setfacl failed")
    with pytest.raises(ps.PrivilegeSeparationError, match="ACL"):
        ps.apply_attempt_acls(paths, runner=failed_run)


def test_atomic_active_rules_reapplies_read_acl(tmp_path):
    calls = []
    active = tmp_path / "rules" / "active.rules"
    active.parent.mkdir()

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    ps.atomic_replace_with_acl(active, b"rules\n", runner=fake_run)
    assert active.read_bytes() == b"rules\n"
    assert any("r--" in token for call in calls for token in call)


def test_process_identity_mismatch_is_not_ready_and_is_terminated(monkeypatch, tmp_path):
    runtime = object.__new__(IsolatedSuricataRuntime)
    runtime.root = tmp_path
    runtime.config = tmp_path / "suricata.yaml"
    runtime.active_rules = tmp_path / "rules" / "active.rules"
    runtime.logdir = tmp_path / "logs"
    runtime.pidfile = tmp_path / "runtime" / "suricata.pid"
    runtime.socket_path = tmp_path / "runtime" / "suricata.sock"
    runtime.process = None
    runtime._old_rules = None
    runtime.service_user = "suricata-g5"
    runtime.service_group = "suricata-g5"
    runtime.expected_uid = 999
    runtime.expected_gid = 982
    runtime.failure_phase = None
    runtime._output_collectors = []
    runtime._check_deadline = lambda: None
    runtime._record_diagnostic = lambda *args, **kwargs: None
    runtime._replace_active_rules = lambda data: None
    runtime._daemon_arguments = lambda: ["suricata"]

    class Process:
        pid = 4242
        stdout = None
        stderr = None
        def __init__(self):
            self.terminated = False
        def poll(self):
            return 0 if self.terminated else None
        def terminate(self):
            self.terminated = True
        def wait(self, timeout=None):
            self.terminated = True
            return 0

    process = Process()
    monkeypatch.setattr("netids.isolated_suricata_runtime.subprocess.Popen", lambda *a, **k: process)
    monkeypatch.setattr("netids.isolated_suricata_runtime.verify_process_identity", lambda *a, **k: (_ for _ in ()).throw(ps.PrivilegeSeparationError("UID mismatch")))
    with pytest.raises(IsolatedRuntimeError, match="identity"):
        runtime._start()
    assert process.terminated is True


def test_shutdown_does_not_remove_attempt_files_when_process_survives(tmp_path):
    runtime = object.__new__(IsolatedSuricataRuntime)
    runtime.process = SimpleNamespace(poll=lambda: None)
    runtime.pidfile = tmp_path / "runtime.pid"
    runtime.socket_path = tmp_path / "runtime.sock"
    runtime.active_rules = tmp_path / "active.rules"
    runtime.diagnostic_path = tmp_path / "diagnostics.jsonl"
    for path in (runtime.pidfile, runtime.socket_path, runtime.active_rules):
        path.write_text("owned", encoding="utf-8")
    runtime._output_collectors = []
    runtime._record_diagnostic = lambda *args, **kwargs: None
    runtime._terminate_child = lambda: False
    runtime._acl_paths = None
    runtime.deadline_monotonic = None
    runtime._command = lambda _command: (_ for _ in ()).throw(IsolatedRuntimeError("shutdown unavailable"))
    assert runtime.shutdown() is False
    assert runtime.active_rules.exists()


def test_audit_security_rejects_non_root_operator(monkeypatch, tmp_path):
    from netids.rule_lifecycle import RuleLifecycle
    monkeypatch.setattr(ps.os, "geteuid", lambda: 1000, raising=False)
    with pytest.raises(ps.PrivilegeSeparationError, match="EUID 0"):
        RuleLifecycle(
            tmp_path / "owner-once.jsonl", isolated_root=tmp_path / "isolated-lab",
        )


def test_operator_path_contains_no_systemctl_mutation():
    source = Path("scripts/operate_frozen_rst_once.py").read_text(encoding="utf-8")
    assert "systemctl" not in source
