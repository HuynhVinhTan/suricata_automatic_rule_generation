import os
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from netids import privilege_separation as ps
from netids import isolated_suricata_runtime as runtime_module
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


def test_proc_status_rejects_mismatched_saved_or_filesystem_identity_fields():
    status = """Name:\tsuricata\nState:\tS (sleeping)\nUid:\t999\t999\t999\t1000\nGid:\t982\t982\t982\t982\nGroups:\t982\n"""
    with pytest.raises(ps.PrivilegeSeparationError, match="identity"):
        ps.verify_proc_identity_text(status)


def _fake_child():
    class Child:
        pid = 4242

        def __init__(self):
            self.alive = True
            self.terminated = False

        def poll(self):
            return None if self.alive else 0

        def terminate(self):
            self.terminated = True
            self.alive = False

        def wait(self, timeout=None):
            self.alive = False
            return 0

        def kill(self):
            self.alive = False

    return Child()


def _identity_runtime():
    runtime = object.__new__(IsolatedSuricataRuntime)
    runtime.process = _fake_child()
    runtime.expected_uid = 999
    runtime.expected_gid = 982
    runtime.failure_phase = None
    runtime._record_diagnostic = lambda *args, **kwargs: None
    return runtime


def _status(uid, gid, groups):
    return ps.parse_proc_status(
        f"Name:\tsuricata\nState:\tS (sleeping)\n"
        f"Uid:\t{uid}\t{uid}\t{uid}\t{uid}\n"
        f"Gid:\t{gid}\t{gid}\t{gid}\t{gid}\n"
        f"Groups:\t{' '.join(str(group) for group in groups)}\n"
    )


def test_identity_transition_accepts_initial_root_then_dedicated_child(monkeypatch):
    runtime = _identity_runtime()
    identities = iter((_status(0, 0, (0,)), _status(999, 982, (982,))))
    monkeypatch.setattr(runtime_module, "read_process_identity", lambda pid: next(identities))
    monkeypatch.setattr(runtime_module.time, "sleep", lambda seconds: None)
    runtime._wait_for_privilege_drop(timeout=5)
    assert runtime.process.terminated is False


def test_identity_transition_rejects_permanent_root_and_terminates(monkeypatch):
    runtime = _identity_runtime()
    monkeypatch.setattr(runtime_module, "read_process_identity", lambda pid: _status(0, 0, (0,)))
    monkeypatch.setattr(runtime_module.time, "sleep", lambda seconds: None)
    with pytest.raises(IsolatedRuntimeError, match="privilege drop"):
        runtime._wait_for_privilege_drop(timeout=0)
    assert runtime.process.terminated is True


@pytest.mark.parametrize(
    "identity, message",
    [(_status(1000, 982, (982,)), "UID"),
     (_status(999, 1000, (1000,)), "GID"),
     (_status(999, 982, (982, 0)), "supplementary root")],
)
def test_identity_transition_rejects_wrong_non_root_identity(monkeypatch, identity, message):
    runtime = _identity_runtime()
    monkeypatch.setattr(runtime_module, "read_process_identity", lambda pid: identity)
    with pytest.raises(IsolatedRuntimeError, match="identity|supplementary root"):
        runtime._wait_for_privilege_drop(timeout=5)
    assert runtime.process.terminated is True


def test_identity_transition_rejects_child_exit_before_drop(monkeypatch):
    runtime = _identity_runtime()
    runtime.process.alive = False
    monkeypatch.setattr(runtime_module, "read_process_identity", lambda pid: _status(0, 0, (0,)))
    with pytest.raises(IsolatedRuntimeError, match="exited"):
        runtime._wait_for_privilege_drop(timeout=5)


def test_identity_gate_does_not_reach_socket_or_replay_before_pass(monkeypatch):
    runtime = _identity_runtime()
    commands = []
    runtime._command = lambda command: commands.append(command) or (_ for _ in ()).throw(
        AssertionError("socket command reached before identity pass")
    )
    monkeypatch.setattr(runtime_module, "read_process_identity", lambda pid: _status(0, 0, (0,)))
    monkeypatch.setattr(runtime_module.time, "sleep", lambda seconds: None)
    with pytest.raises(IsolatedRuntimeError):
        runtime._wait_for_privilege_drop(timeout=0)
    assert commands == []


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


def test_external_reference_is_rejected_instead_of_receiving_acl(tmp_path):
    root = tmp_path / "isolated"
    root.mkdir()
    external = tmp_path / "external.config"
    external.write_text("external", encoding="utf-8")
    with pytest.raises(ps.PrivilegeSeparationError, match="escapes|outside"):
        ps.referenced_configuration_files(
            {"classification-file": str(external)},
            root / "suricata.yaml", allowed_root=root,
        )


def test_reference_path_traversal_is_rejected(tmp_path):
    root = tmp_path / "isolated"
    root.mkdir()
    outside = tmp_path / "outside.config"
    outside.write_text("outside", encoding="utf-8")
    with pytest.raises(ps.PrivilegeSeparationError, match="escapes|outside"):
        ps.referenced_configuration_files(
            {"classification-file": "../outside.config"},
            root / "suricata.yaml", allowed_root=root,
        )


def test_symlink_reference_is_rejected(tmp_path):
    root = tmp_path / "isolated"
    root.mkdir()
    real = root / "real.config"
    real.write_text("real", encoding="utf-8")
    link = root / "link.config"
    try:
        link.symlink_to(real)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable")
    with pytest.raises(ps.PrivilegeSeparationError, match="symlink"):
        ps.referenced_configuration_files(
            {"classification-file": "link.config"},
            root / "suricata.yaml", allowed_root=root,
        )


def test_referenced_configuration_is_copied_and_yaml_is_rewritten(tmp_path):
    root = tmp_path / "isolated"
    root.mkdir()
    source = root / "suricata.yaml"
    classification = root / "config" / "classification.config"
    classification.parent.mkdir()
    classification.write_text("class", encoding="utf-8")
    source.write_text("source", encoding="utf-8")
    confined = ps.confine_configuration_references(
        {"classification-file": "config/classification.config"}, source,
        attempt_root=root / "attempts" / "one", allowed_root=root,
    )
    copied = root / "attempts" / "one" / "references" / "config" / "classification.config"
    assert copied.read_text(encoding="utf-8") == "class"
    assert confined["classification-file"] == "references/config/classification.config"
    assert classification.read_text(encoding="utf-8") == "class"


def test_nested_referenced_files_get_execute_only_parent_acls(tmp_path):
    root = tmp_path / "attempt"
    nested = root / "references" / "nested"
    nested.mkdir(parents=True)
    reference = nested / "classification.config"
    reference.write_text("classification", encoding="utf-8")
    paths = ps.AttemptAccessPaths(
        attempt_root=root,
        runtime_dir=root / "runtime",
        rules_dir=root / "rules",
        active_rules=root / "rules" / "active.rules",
        logs_dir=root / "logs",
        effective_config=root / "suricata.yaml",
        referenced_files=(reference,),
    )
    specs = {path: permission for permission, path in ps._access_specs(paths, "suricata-g5")}
    assert specs[root / "references"] == "--x"
    assert specs[nested] == "--x"
    assert specs[reference] == "r--"
    assert specs[root / "references"] != "r--"
    assert specs[nested] != "r--"


def test_runtime_output_acl_is_file_scoped_and_log_directory_is_not_writable(tmp_path):
    root = tmp_path / "attempt"
    runtime_dir = root / "runtime"
    rules_dir = root / "rules"
    logs_dir = root / "logs"
    for directory in (runtime_dir, rules_dir, logs_dir):
        directory.mkdir(parents=True)
    active = rules_dir / "active.rules"
    config = root / "suricata.yaml"
    output = logs_dir / "eve.json"
    active.write_text("baseline", encoding="utf-8")
    config.write_text("{}", encoding="utf-8")
    output.write_text("", encoding="utf-8")
    paths = ps.AttemptAccessPaths(
        attempt_root=root, runtime_dir=runtime_dir, rules_dir=rules_dir,
        active_rules=active, logs_dir=logs_dir, effective_config=config,
        runtime_output_files=(output,),
    )

    specs = {path: permission for permission, path in ps._access_specs(paths, "suricata-g5")}

    assert specs[logs_dir] == "--x"
    assert specs[output] == "rw-"


def test_runtime_output_paths_include_nested_logging_files(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    outputs = ps.runtime_output_paths(
        {
            "outputs": [{"eve-log": {"enabled": True, "filename": "eve.json"}}],
            "logging": {"outputs": [{"file": {"enabled": True, "filename": "suricata.log"}}]},
        },
        logs,
    )
    assert outputs == (logs / "eve.json", logs / "suricata.log")


def test_runtime_output_access_verification_requires_read_write_acl(tmp_path):
    output = tmp_path / "eve.json"
    output.write_text("", encoding="utf-8")
    paths = ps.AttemptAccessPaths(
        attempt_root=tmp_path, runtime_dir=tmp_path, rules_dir=tmp_path,
        active_rules=output, logs_dir=tmp_path, effective_config=output,
        runtime_output_files=(output,),
    )

    def runner(argv, **kwargs):
        return SimpleNamespace(
            returncode=0,
            stdout="user:suricata-g5:rw-\nmask::rw-\n",
            stderr="",
        )

    assert ps.verify_runtime_output_access(paths, runner=runner) is True


def test_runtime_output_access_rejects_read_only_effective_acl(tmp_path):
    output = tmp_path / "eve.json"
    output.write_text("", encoding="utf-8")
    paths = ps.AttemptAccessPaths(
        attempt_root=tmp_path, runtime_dir=tmp_path, rules_dir=tmp_path,
        active_rules=output, logs_dir=tmp_path, effective_config=output,
        runtime_output_files=(output,),
    )

    def runner(argv, **kwargs):
        return SimpleNamespace(
            returncode=0,
            stdout="user:suricata-g5:rw- #effective:r--\nmask::rw-\n",
            stderr="",
        )

    with pytest.raises(ps.PrivilegeSeparationError, match="cannot open"):
        ps.verify_runtime_output_access(paths, runner=runner)


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "path_escape", "unexpected"])
def test_runtime_output_artifacts_fail_closed_before_startup(tmp_path, kind):
    logs = tmp_path / "logs"
    logs.mkdir()
    expected = logs / "eve.json"
    if kind == "symlink":
        outside = tmp_path / "outside.json"
        outside.write_text("outside", encoding="utf-8")
        try:
            expected.symlink_to(outside)
        except (OSError, NotImplementedError):
            pytest.skip("symlink creation is unavailable")
    elif kind == "hardlink":
        outside = tmp_path / "outside.json"
        outside.write_text("outside", encoding="utf-8")
        expected.hardlink_to(outside)
    elif kind == "path_escape":
        with pytest.raises(ps.PrivilegeSeparationError, match="unsafe|outside|escape"):
            ps.prepare_runtime_output_files(
                {"outputs": [{"eve-log": {"enabled": True, "filename": "../eve.json"}}]},
                logs,
            )
        return
    else:
        (logs / "unexpected.txt").write_text("unexpected", encoding="utf-8")

    with pytest.raises(ps.PrivilegeSeparationError, match="unsafe|hardlink|unexpected|symlink"):
        ps.prepare_runtime_output_files(
            {"outputs": [{"eve-log": {"enabled": True, "filename": "eve.json"}}]},
            logs,
        )


def test_primary_runtime_failure_is_not_replaced_by_cleanup_failure(tmp_path):
    runtime = object.__new__(IsolatedSuricataRuntime)
    runtime.diagnostic_path = tmp_path / "diagnostics.jsonl"
    runtime.failure_phase = None
    runtime.primary_failure_phase = None
    runtime.primary_failure_reason = None
    runtime._record_diagnostic = IsolatedSuricataRuntime._record_diagnostic.__get__(runtime)

    runtime._record_diagnostic("startup", status="failed", error="daemon exited")
    runtime._record_diagnostic("cleanup", status="failed", error="ACL cleanup failed")

    assert runtime.failure_phase == "startup"
    assert runtime.primary_failure_phase == "startup"
    assert runtime.primary_failure_reason == "daemon exited"


def test_nested_yaml_dependencies_are_confined_and_rewritten_recursively(tmp_path):
    root = tmp_path / "isolated"
    source = root / "suricata.yaml"
    source.parent.mkdir()
    include = root / "config" / "main.yaml"
    nested_include = include.parent / "nested" / "child.yaml"
    classification = root / "data" / "classification.config"
    rule = root / "rules" / "child.rules"
    for path in (include, nested_include, classification, rule):
        path.parent.mkdir(parents=True, exist_ok=True)
    source.write_text("include: config/main.yaml\n", encoding="utf-8")
    include.write_text(
        "classification-file: ../data/classification.config\n"
        "include: nested/child.yaml\n",
        encoding="utf-8",
    )
    nested_include.write_text(
        "default-rule-path: ../../rules\nrule-files: [child.rules]\n",
        encoding="utf-8",
    )
    classification.write_text("class", encoding="utf-8")
    rule.write_text("alert tcp any any -> any any (msg:\"child\";)\n", encoding="utf-8")

    confined = ps.confine_configuration_references(
        {"include": "config/main.yaml"}, source,
        attempt_root=root / "attempts" / "one", allowed_root=root,
    )

    attempt = root / "attempts" / "one"
    copied_include = attempt / "references" / "config" / "main.yaml"
    copied_nested = attempt / "references" / "config" / "nested" / "child.yaml"
    copied_classification = attempt / "references" / "data" / "classification.config"
    copied_rule = attempt / "references" / "rules" / "child.rules"
    assert confined["include"] == "references/config/main.yaml"
    assert copied_include.exists()
    assert copied_nested.exists()
    assert copied_classification.read_text(encoding="utf-8") == "class"
    assert copied_rule.exists()
    assert yaml.safe_load(copied_include.read_text(encoding="utf-8")) == {
        "classification-file": "../data/classification.config",
        "include": "nested/child.yaml",
    }
    assert yaml.safe_load(copied_nested.read_text(encoding="utf-8")) == {
        "default-rule-path": "../../rules",
        "rule-files": ["child.rules"],
    }
    assert ps.referenced_configuration_files(
        confined,
        attempt / "suricata.yaml",
        allowed_root=attempt,
    ) == (copied_include, copied_classification, copied_nested, copied_rule)


def test_nested_yaml_include_escape_is_rejected_before_copy(tmp_path):
    root = tmp_path / "isolated"
    source = root / "suricata.yaml"
    include = root / "config" / "main.yaml"
    outside = tmp_path / "outside.yaml"
    root.mkdir()
    include.parent.mkdir()
    source.write_text("include: config/main.yaml\n", encoding="utf-8")
    include.write_text("include: ../../outside.yaml\n", encoding="utf-8")
    outside.write_text("classification-file: missing.config\n", encoding="utf-8")
    with pytest.raises(ps.PrivilegeSeparationError, match="escapes|outside"):
        ps.confine_configuration_references(
            {"include": "config/main.yaml"}, source,
            attempt_root=root / "attempts" / "one", allowed_root=root,
        )


def test_acl_application_uses_argument_arrays_and_no_audit_path(tmp_path):
    calls = []
    paths = ps.AttemptAccessPaths(
        attempt_root=tmp_path / "attempt",
        runtime_dir=tmp_path / "attempt" / "runtime",
        rules_dir=tmp_path / "attempt" / "rules",
        active_rules=tmp_path / "attempt" / "rules" / "active.rules",
        logs_dir=tmp_path / "attempt" / "logs",
        effective_config=tmp_path / "attempt" / "suricata.yaml",
        referenced_files=(tmp_path / "attempt" / "classification.config",),
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
    assert any("--x" in token for call in calls for token in call[0])
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


def _acl_paths(tmp_path):
    root = tmp_path / "attempt"
    runtime_dir = root / "runtime"
    rules_dir = root / "rules"
    logs_dir = root / "logs"
    runtime_dir.mkdir(parents=True)
    rules_dir.mkdir()
    logs_dir.mkdir()
    active = rules_dir / "active.rules"
    config = root / "suricata.yaml"
    reference = root / "references" / "nested" / "classification.config"
    reference.parent.mkdir(parents=True)
    active.write_text("baseline", encoding="utf-8")
    config.write_text("{}", encoding="utf-8")
    reference.write_text("classification", encoding="utf-8")
    return ps.AttemptAccessPaths(
        attempt_root=root, runtime_dir=runtime_dir, rules_dir=rules_dir,
        active_rules=active, logs_dir=logs_dir, effective_config=config,
        referenced_files=(reference,),
    )


@pytest.mark.parametrize("failure_index", [1, 4, 9])
def test_acl_application_rolls_back_partial_changes_in_reverse_order(tmp_path, failure_index):
    paths = _acl_paths(tmp_path)
    setfacl_calls = []
    initial_targets = []

    def runner(argv, **kwargs):
        if argv[0] == "getfacl":
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        setfacl_calls.append(argv)
        if "-m" in argv:
            initial_targets.append(argv[-1])
        if len([call for call in setfacl_calls if "-m" in call]) == failure_index:
            return SimpleNamespace(returncode=1, stdout="", stderr="injected ACL failure")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    with pytest.raises(ps.PrivilegeSeparationError, match="ACL application"):
        ps.apply_attempt_acls(paths, runner=runner)
    rollback_targets = [call[-1] for call in setfacl_calls if "-x" in call]
    assert rollback_targets == list(reversed(initial_targets[:failure_index - 1]))


def test_acl_transaction_preserves_preexisting_entry_and_rolls_back_new_entries(tmp_path):
    paths = _acl_paths(tmp_path)
    calls = []
    preexisting = str(paths.attempt_root)

    def runner(argv, **kwargs):
        calls.append(argv)
        if argv[0] == "getfacl":
            output = f"user:suricata-g5:r-x\n" if argv[-1] == preexisting else ""
            return SimpleNamespace(returncode=0, stdout=output, stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    transaction = ps.apply_attempt_acls(paths, runner=runner)
    transaction.rollback()
    call_count = len(calls)
    transaction.rollback()
    assert len(calls) == call_count
    assert any("user:suricata-g5:r-x" in token for call in calls for token in call)
    assert not any("-x" in call and preexisting in call for call in calls)


def test_acl_transaction_reports_rollback_failure_separately(tmp_path):
    paths = _acl_paths(tmp_path)
    setfacl_calls = []
    initial_count = 0

    def runner(argv, **kwargs):
        nonlocal initial_count
        if argv[0] == "getfacl":
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        setfacl_calls.append(argv)
        if "-m" in argv:
            initial_count += 1
        return SimpleNamespace(
            returncode=1 if "-x" in argv or initial_count == 3 else 0,
            stdout="", stderr="rollback failed",
        )

    with pytest.raises(ps.PrivilegeSeparationError, match="rollback"):
        ps.apply_attempt_acls(paths, runner=runner)


def test_acl_transaction_fails_closed_when_rollback_cannot_be_verified(tmp_path):
    paths = _acl_paths(tmp_path)
    rollback_started = False

    def runner(argv, **kwargs):
        nonlocal rollback_started
        if argv[0] == "getfacl":
            output = "user:suricata-g5:r--\n" if rollback_started else ""
            return SimpleNamespace(returncode=0, stdout=output, stderr="")
        if "-x" in argv:
            rollback_started = True
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    transaction = ps.apply_attempt_acls(paths, runner=runner)
    with pytest.raises(ps.PrivilegeSeparationError, match="verification"):
        transaction.rollback()


def test_acl_rejects_symlinked_reference_directory(tmp_path):
    paths = _acl_paths(tmp_path)
    nested = paths.attempt_root / "references" / "nested"
    (nested / "classification.config").unlink()
    nested.rmdir()
    try:
        nested.symlink_to(tmp_path / "outside", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable")
    with pytest.raises(ps.PrivilegeSeparationError, match="symlink|outside"):
        ps.apply_attempt_acls(paths, runner=lambda *args, **kwargs: SimpleNamespace(
            returncode=0, stdout="", stderr="",
        ))


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
    runtime.attempt_root = tmp_path
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
    monkeypatch.setattr("netids.isolated_suricata_runtime.read_process_identity", lambda *a, **k: _status(1000, 982, (982,)))
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
