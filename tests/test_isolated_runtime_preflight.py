"""Isolated runtime fail-closed preflight tests: never start Suricata in CI."""

import io
import hashlib
import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from netids import isolated_suricata_runtime as runtime_module
from netids.isolated_suricata_runtime import (
    IsolatedSuricataRuntime, IsolatedRuntimeError, is_verified_vm1_host,
    validate_unix_socket_path,
)
from netids.privilege_separation import PrivilegeSeparationError
from netids.latency import LatencyTrace
from scripts.operate_isolated_once import (
    OperationError, _require_candidate_baseline, production_snapshot,
)
from scripts import operate_frozen_rst_once
from netids.lifecycle_ed25519 import generate_encrypted_keypair


def test_runtime_refuses_non_vm1_even_with_synthetic_pcap(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "netids.isolated_suricata_runtime.socket.gethostname",
        lambda: "ci-runner-not-vm1",
    )
    with pytest.raises(IsolatedRuntimeError, match="Wrong host"):
        IsolatedSuricataRuntime(
            config=tmp_path / "isolated.yaml",
            attack_pcap=tmp_path / "attack.pcap",
            attack_sha256="a" * 64,
            normal_pcap=tmp_path / "normal.pcap",
            normal_sha256="b" * 64,
        )


def test_production_snapshot_cannot_be_redirected_to_fake_config(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "scripts.operate_isolated_once.is_verified_vm1_host",
        lambda: True,
    )
    fake_yaml = tmp_path / "suricata.yaml"
    fake_rules = tmp_path / "rules.rules"
    fake_yaml.write_text("{}")
    fake_rules.write_text("# fake")
    with pytest.raises(OperationError, match="real VM1 production YAML"):
        production_snapshot(fake_yaml, fake_rules)


def test_loaded_rules_gate_rejects_failed_or_unexpected_counts():
    runtime = object.__new__(IsolatedSuricataRuntime)
    runtime._command = lambda command: [
        {"id": 0, "rules_loaded": 1, "rules_failed": 0, "rules_skipped": 0}
    ]
    assert runtime._rules_loaded(1) is True
    assert runtime._rules_loaded(0) is False
    runtime._command = lambda command: [
        {"id": 0, "rules_loaded": 1, "rules_failed": 1, "rules_skipped": 0}
    ]
    assert runtime._rules_loaded(1) is False
    runtime._command = lambda command: "success"
    assert runtime._rules_loaded(1) is False


def test_verified_vm1_requires_both_actual_hostname_and_exact_ens33_ip(monkeypatch):
    monkeypatch.setattr(
        "netids.isolated_suricata_runtime.socket.gethostname",
        lambda: "tanhv",
    )
    calls = []
    def fake_run(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(
            returncode=0,
            stdout="2: ens33    inet 192.168.10.10/24 brd 192.168.10.255 scope global ens33",
        )
    monkeypatch.setattr("netids.isolated_suricata_runtime.subprocess.run", fake_run)
    assert is_verified_vm1_host() is True
    assert calls == [["ip", "-4", "-o", "addr", "show", "dev", "ens33"]]

    monkeypatch.setattr(
        "netids.isolated_suricata_runtime.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0, stdout="2: ens33 inet 192.168.10.11/24 scope global ens33",
        ),
    )
    assert is_verified_vm1_host() is False

    monkeypatch.setattr(
        "netids.isolated_suricata_runtime.socket.gethostname",
        lambda: "other-vm",
    )
    assert is_verified_vm1_host() is False


def test_vm1_identity_fails_closed_when_ip_command_is_unavailable(monkeypatch):
    monkeypatch.setattr(
        "netids.isolated_suricata_runtime.socket.gethostname",
        lambda: "tanhv",
    )
    def missing_ip(*args, **kwargs):
        raise FileNotFoundError("ip missing")
    monkeypatch.setattr("netids.isolated_suricata_runtime.subprocess.run", missing_ip)
    assert is_verified_vm1_host() is False


def test_run_forwards_supplied_working_directory(monkeypatch, tmp_path):
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr("netids.isolated_suricata_runtime.subprocess.run", fake_run)
    assert runtime_module._run(["suricata", "-V"], cwd=tmp_path).stdout == "ok"
    assert calls[0][1]["cwd"] == tmp_path


def test_candidate_syntax_validation_uses_exact_attempt_root(monkeypatch, tmp_path):
    attempt = tmp_path / "attempts" / "g5r3"
    references = attempt / "references"
    (attempt / "runtime").mkdir(parents=True)
    (attempt / "logs").mkdir()
    (tmp_path / "runtime").mkdir()
    references.mkdir()
    (references / "classification.config").write_text("classification", encoding="utf-8")
    (references / "reference.config").write_text("reference", encoding="utf-8")
    config = attempt / "suricata.yaml"
    config.write_text(
        "classification-file: references/classification.config\n"
        "reference-config-file: references/reference.config\n",
        encoding="utf-8",
    )
    pcap = tmp_path / "attack.pcap"
    pcap.write_bytes(b"verified-pcap")
    runtime = object.__new__(IsolatedSuricataRuntime)
    runtime.attempt_root = attempt
    runtime.root = tmp_path
    runtime.config = config
    runtime.attack_pcap = pcap
    runtime.attack_sha256 = hashlib.sha256(pcap.read_bytes()).hexdigest()
    runtime.suricata = "/usr/bin/suricata"
    runtime.logdir = attempt / "logs"
    runtime.deadline_monotonic = None
    runtime._check_deadline = lambda: None
    runtime._record_diagnostic = lambda *args, **kwargs: None
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        cwd = kwargs["cwd"]
        document = yaml.safe_load((cwd / "suricata.yaml").read_text(encoding="utf-8"))
        assert (cwd / document["classification-file"]).is_file()
        assert (cwd / document["reference-config-file"]).is_file()
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("netids.isolated_suricata_runtime._run", fake_run)
    assert runtime._validate_impl('alert tcp any any -> any any (msg:"candidate";)') is True
    assert calls[0][1]["cwd"] == attempt


def test_suricatasc_commands_use_exact_attempt_root(monkeypatch, tmp_path):
    attempt = tmp_path / "attempt"
    attempt.mkdir()
    runtime = object.__new__(IsolatedSuricataRuntime)
    runtime.attempt_root = attempt
    runtime.socket_path = attempt / "runtime" / "socket"
    runtime.suricatasc = "/usr/bin/suricatasc"
    runtime.deadline_monotonic = None
    runtime._check_deadline = lambda: None
    runtime._record_diagnostic = lambda *args, **kwargs: None
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout='{"return":"OK","message":"ok"}', stderr="")

    monkeypatch.setattr("netids.isolated_suricata_runtime._run", fake_run)
    assert runtime._command("version") == "ok"
    assert calls[0][1]["cwd"] == attempt


def test_candidate_baseline_must_match_actual_production_rules_hash():
    candidate = {"baseline_rules_sha256": "a" * 64}
    snapshot = {"production_rules_sha256": "a" * 64}
    _require_candidate_baseline(candidate, snapshot)
    with pytest.raises(OperationError, match="baseline rules"):
        _require_candidate_baseline(candidate, {"production_rules_sha256": "b" * 64})


def test_candidate_baseline_missing_hash_fails_closed():
    with pytest.raises(OperationError, match="baseline rules"):
        _require_candidate_baseline({}, {"production_rules_sha256": "a" * 64})


def test_daemon_uses_af_packet_only_and_keeps_exclusive_syntax_rule_path_offline(tmp_path):
    runtime = object.__new__(IsolatedSuricataRuntime)
    runtime.suricata = "/usr/bin/suricata"
    runtime.config = tmp_path / "isolated.yaml"
    runtime.active_rules = tmp_path / "rules" / "active.rules"
    runtime.logdir = tmp_path / "logs"
    runtime.pidfile = tmp_path / "runtime" / "suricata.pid"

    arguments = runtime._daemon_arguments()

    assert "--af-packet=lo" in arguments
    assert "--unix-socket=" not in " ".join(arguments)
    assert "-S" not in arguments and "-s" not in arguments
    validation = runtime._validation_rule_arguments(tmp_path / "runtime" / "candidate.rules")
    assert validation[validation.index("-S") + 1] == str(tmp_path / "runtime" / "candidate.rules")


def test_isolated_config_declares_only_active_rules_and_attempt_socket(tmp_path, monkeypatch):
    monkeypatch.setattr("netids.isolated_suricata_runtime.validate_unix_socket_path", lambda path: path)
    runtime = object.__new__(IsolatedSuricataRuntime)
    runtime.root = tmp_path
    runtime.config = tmp_path / "isolated.yaml"
    runtime.active_rules = tmp_path / "rules" / "active.rules"
    runtime.socket_path = tmp_path / "runtime" / "suricata.sock"
    runtime.config.write_text(
        """default-rule-path: {rules}
rule-files:
  - active.rules
unix-command:
  enabled: yes
  filename: {socket}
af-packet:
  - interface: lo
outputs:
  - eve-log:
      enabled: yes
      filename: eve.json
""".format(rules=tmp_path / "rules", socket=tmp_path / "runtime" / "suricata.sock"),
        encoding="utf-8",
    )

    runtime._validate_isolated_configuration()


def test_attempt_namespace_rewrites_effective_config_without_touching_template(tmp_path, monkeypatch):
    monkeypatch.setattr("netids.isolated_suricata_runtime.validate_unix_socket_path", lambda path: path)
    root = tmp_path / "isolated"
    root.mkdir()
    template = root / "isolated.yaml"
    template.write_text(
        "default-rule-path: {root}/rules\n"
        "rule-files:\n"
        "  - active.rules\n"
        "unix-command:\n"
        "  enabled: yes\n"
        "  filename: {root}/runtime/lab-suricata.socket\n"
        "af-packet:\n"
        "  - interface: lo\n"
        "outputs:\n"
        "  - eve-log:\n"
        "      enabled: yes\n"
        "      filename: eve.json\n".format(root=root),
        encoding="utf-8",
    )
    original = template.read_bytes()
    runtime = object.__new__(IsolatedSuricataRuntime)
    runtime.root = root
    runtime.config_source = template
    runtime.attempt_id = "attempt-20261125-01"
    runtime.attempt_root = root / "attempts" / runtime.attempt_id
    runtime.config = runtime.attempt_root / "suricata.yaml"
    runtime.active_rules = runtime.attempt_root / "rules" / "active.rules"
    runtime.socket_path = runtime.attempt_root / "runtime" / "lab-suricata.socket"
    runtime.pidfile = runtime.attempt_root / "runtime" / "lab-suricata.pid"
    runtime.logdir = runtime.attempt_root / "logs"
    runtime.diagnostic_path = runtime.logdir / "runtime-diagnostics.jsonl"

    runtime._prepare_attempt_namespace()

    assert template.read_bytes() == original
    assert runtime.config.read_bytes().startswith(b"%YAML 1.1\n---\n")
    effective = yaml.safe_load(runtime.config.read_text(encoding="utf-8"))
    assert effective["default-rule-path"] == str(runtime.active_rules.parent)
    assert effective["rule-files"] == ["active.rules"]
    assert effective["unix-command"]["filename"] == str(runtime.socket_path)
    assert runtime.config.is_relative_to(runtime.attempt_root)
    assert runtime.diagnostic_path.is_relative_to(runtime.attempt_root)


def test_attempt_namespace_refuses_reuse_and_preserves_prior_attempt(tmp_path, monkeypatch):
    monkeypatch.setattr("netids.isolated_suricata_runtime.validate_unix_socket_path", lambda path: path)
    root = tmp_path / "isolated"
    root.mkdir()
    template = root / "isolated.yaml"
    template.write_text(
        "default-rule-path: rules\n"
        "rule-files: [active.rules]\n"
        "unix-command: {enabled: true, filename: runtime/socket}\n"
        "af-packet: [{interface: lo}]\n"
        "outputs: [{eve-log: {enabled: true, filename: eve.json}}]\n",
        encoding="utf-8",
    )

    def make_runtime():
        runtime = object.__new__(IsolatedSuricataRuntime)
        runtime.root = root
        runtime.config_source = template
        runtime.attempt_id = "attempt-01"
        runtime.attempt_root = root / "attempts" / runtime.attempt_id
        runtime.config = runtime.attempt_root / "suricata.yaml"
        runtime.active_rules = runtime.attempt_root / "rules" / "active.rules"
        runtime.socket_path = runtime.attempt_root / "runtime" / "socket"
        runtime.pidfile = runtime.attempt_root / "runtime" / "pid"
        runtime.logdir = runtime.attempt_root / "logs"
        runtime.diagnostic_path = runtime.logdir / "runtime-diagnostics.jsonl"
        return runtime

    runtime = make_runtime()
    runtime._prepare_attempt_namespace()
    marker = runtime.attempt_root / "failure.json"
    marker.write_text("preserve", encoding="utf-8")

    with pytest.raises(IsolatedRuntimeError, match="already exists"):
        make_runtime()._prepare_attempt_namespace()
    assert marker.read_text(encoding="utf-8") == "preserve"


@pytest.mark.parametrize("reference", ["missing/classification.config", "../outside.config"])
def test_attempt_namespace_rejects_missing_or_unsafe_references(tmp_path, monkeypatch, reference):
    monkeypatch.setattr("netids.isolated_suricata_runtime.validate_unix_socket_path", lambda path: path)
    root = tmp_path / "isolated"
    root.mkdir()
    if reference.startswith("../"):
        (tmp_path / "outside.config").write_text("outside", encoding="utf-8")
    template = root / "isolated.yaml"
    template.write_text(
        "classification-file: " + reference + "\n"
        "rule-files: [active.rules]\n"
        "unix-command: {enabled: true, filename: runtime/socket}\n"
        "af-packet: [{interface: lo}]\n"
        "outputs: [{eve-log: {enabled: true, filename: eve.json}}]\n",
        encoding="utf-8",
    )
    runtime = object.__new__(IsolatedSuricataRuntime)
    runtime.root = root
    runtime.config_source = template
    runtime.attempt_id = "attempt-unsafe-reference"
    runtime.attempt_root = root / "attempts" / runtime.attempt_id
    runtime.config = runtime.attempt_root / "suricata.yaml"
    runtime.active_rules = runtime.attempt_root / "rules" / "active.rules"
    runtime.socket_path = runtime.attempt_root / "runtime" / "socket"
    runtime.pidfile = runtime.attempt_root / "runtime" / "pid"
    runtime.logdir = runtime.attempt_root / "logs"
    runtime.diagnostic_path = runtime.logdir / "runtime-diagnostics.jsonl"
    with pytest.raises(IsolatedRuntimeError, match="effective attempt configuration"):
        runtime._prepare_attempt_namespace()


def test_historical_sid9103003_config_declares_loopback_af_packet():
    config = yaml.safe_load(Path("configs/suricata/isolated-lifecycle-9103003.yaml").read_text(encoding="utf-8"))
    assert config["af-packet"] == [{"interface": "lo"}]


def test_vm1_socket_path_limit_is_checked_in_encoded_bytes():
    long_path = Path(
        "/home/tanhv/suricata-rule-review/isolated-lifecycle-9103005/"
        "attempts/g5-readiness-20261125-01/runtime/lab-suricata.socket"
    )
    short_path = Path(
        "/home/tanhv/suricata-rule-review/isolated-lifecycle-9103005/"
        "attempts/g5r1/runtime/lab-suricata.socket"
    )
    assert len(os.fsencode(str(long_path))) == 121
    assert len(os.fsencode(str(short_path))) == 101
    with pytest.raises(ValueError, match="UNIX socket pathname"):
        validate_unix_socket_path(long_path)
    validate_unix_socket_path(short_path)


def test_frozen_operator_rejects_long_vm1_socket_before_lifecycle_or_nonce(
    monkeypatch, tmp_path,
):
    monkeypatch.setattr(operate_frozen_rst_once, "require_root_operator_if_supported", lambda: None)
    monkeypatch.setattr(operate_frozen_rst_once, "is_verified_vm1_host", lambda: True)
    monkeypatch.setattr(
        operate_frozen_rst_once,
        "_read_json",
        lambda _path: (_ for _ in ()).throw(AssertionError("readiness must precede lifecycle inputs")),
    )
    lifecycle_created = []
    monkeypatch.setattr(
        operate_frozen_rst_once,
        "RuleLifecycle",
        lambda *args, **kwargs: lifecycle_created.append(True),
    )
    root = Path(
        "/home/tanhv/suricata-rule-review/isolated-lifecycle-9103005"
    )
    attempt_id = "g5-readiness-20261125-01"
    with pytest.raises(OperationError, match="UNIX socket pathname"):
        operate_frozen_rst_once.execute_frozen_once(
            candidate_file=tmp_path / "candidate.json",
            replay_file=tmp_path / "replay.json",
            owner_file=tmp_path / "owner.json",
            replay_public_file=tmp_path / "replay.pub.pem",
            owner_public_file=tmp_path / "owner.pub.pem",
            runtime_public_file=tmp_path / "runtime.pub.pem",
            production_yaml=tmp_path / "suricata.yaml",
            production_rules=tmp_path / "rules.rules",
            isolated_yaml=tmp_path / "isolated.yaml",
            isolated_root=root,
            attempt_id=attempt_id,
            probe_specs=[],
            audit_path=root / "audit" / "owner-once.jsonl",
            failure_path=root / "attempts" / attempt_id / "failure.json",
            runtime_private_pem=b"private",
            runtime_private_password=b"password",
        )
    assert lifecycle_created == []


def test_frozen_operator_rejects_non_root_before_any_side_effect(monkeypatch, tmp_path):
    monkeypatch.setattr(operate_frozen_rst_once, "is_verified_vm1_host", lambda: True)
    monkeypatch.setattr(
        operate_frozen_rst_once,
        "require_root_operator_if_supported",
        lambda: (_ for _ in ()).throw(PrivilegeSeparationError("root operator with EUID 0 is required")),
    )
    input_reads = []
    monkeypatch.setattr(
        operate_frozen_rst_once,
        "_read_json",
        lambda path: input_reads.append(path) or (_ for _ in ()).throw(
            AssertionError("non-root guard must precede input reads")
        ),
    )
    lifecycle_created = []
    monkeypatch.setattr(
        operate_frozen_rst_once,
        "RuleLifecycle",
        lambda *args, **kwargs: lifecycle_created.append(True),
    )
    isolated = tmp_path / "isolated"
    audit = isolated / "audit" / "owner-once.jsonl"
    attempt = isolated / "attempts" / "attempt-non-root"
    with pytest.raises(OperationError, match="EUID 0"):
        operate_frozen_rst_once.execute_frozen_once(
            candidate_file=tmp_path / "candidate.json",
            replay_file=tmp_path / "replay.json",
            owner_file=tmp_path / "owner.json",
            replay_public_file=tmp_path / "replay.pub.pem",
            owner_public_file=tmp_path / "owner.pub.pem",
            runtime_public_file=tmp_path / "runtime.pub.pem",
            production_yaml=tmp_path / "suricata.yaml",
            production_rules=tmp_path / "rules.rules",
            isolated_yaml=tmp_path / "isolated.yaml",
            isolated_root=isolated,
            attempt_id="attempt-non-root",
            probe_specs=[], audit_path=audit, failure_path=attempt / "failure.json",
            runtime_private_pem=b"private", runtime_private_password=b"password",
        )
    assert input_reads == []
    assert lifecycle_created == []
    assert not audit.exists()
    assert not attempt.exists()


def test_startup_failure_preserves_bounded_daemon_diagnostics(monkeypatch, tmp_path):
    runtime = object.__new__(IsolatedSuricataRuntime)
    runtime.root = tmp_path
    runtime.attempt_root = tmp_path / "attempt"
    runtime.config = runtime.attempt_root / "isolated.yaml"
    runtime.active_rules = runtime.attempt_root / "rules" / "active.rules"
    runtime.logdir = runtime.attempt_root / "logs"
    runtime.pidfile = runtime.attempt_root / "runtime" / "suricata.pid"
    runtime.socket_path = runtime.attempt_root / "runtime" / "suricata.sock"
    runtime.process = None
    runtime._old_rules = None
    runtime.active_rules.parent.mkdir(parents=True)
    runtime.diagnostic_path = tmp_path / "logs" / "runtime-diagnostics.jsonl"
    runtime.failure_phase = None
    runtime._output_collectors = []
    runtime._check_deadline = lambda: None
    runtime._record_diagnostic = IsolatedSuricataRuntime._record_diagnostic.__get__(runtime)
    runtime._daemon_arguments = IsolatedSuricataRuntime._daemon_arguments.__get__(runtime)
    runtime.suricata = "/usr/bin/suricata"

    class FailedProcess:
        stdout = io.BytesIO(b"initialization failed: missing AF_PACKET capability\n")
        stderr = io.BytesIO(b"secret=do-not-log\n")

        @staticmethod
        def poll():
            return 23

    def fake_popen(arguments, **kwargs):
        assert kwargs["stdout"] == subprocess.PIPE
        assert kwargs["stderr"] == subprocess.PIPE
        assert kwargs["cwd"] == runtime.attempt_root
        return FailedProcess()

    monkeypatch.setattr("netids.isolated_suricata_runtime.subprocess.Popen", fake_popen)

    with pytest.raises(IsolatedRuntimeError, match="startup"):
        runtime._start()

    diagnostics = runtime.diagnostic_path.read_text(encoding="utf-8")
    assert "initialization failed" in diagnostics
    assert "do-not-log" not in diagnostics
    record = json.loads(diagnostics.splitlines()[-1])
    assert record["phase"] == "startup"
    assert record["exit_status"] == 23


def test_reload_failure_is_recorded_with_phase_and_socket_error(tmp_path):
    runtime = object.__new__(IsolatedSuricataRuntime)
    runtime.root = tmp_path
    runtime.active_rules = tmp_path / "rules" / "active.rules"
    runtime.active_rules.parent.mkdir()
    runtime._old_rules = b"# empty\n"
    runtime.sid = 9103005
    runtime.rule_sha256 = "a" * 64
    runtime.process = SimpleNamespace(poll=lambda: None)
    runtime.failure_phase = None
    runtime.diagnostic_path = tmp_path / "logs" / "runtime-diagnostics.jsonl"
    runtime._record_diagnostic = IsolatedSuricataRuntime._record_diagnostic.__get__(runtime)
    runtime._measure_bool = lambda _name, _component, operation: operation()
    runtime._command = lambda _command: (_ for _ in ()).throw(
        IsolatedRuntimeError("socket command failed: reload rejected")
    )

    assert runtime._rollback_impl(tmp_path / "candidate.rules", 9103005, "a" * 64) is False

    records = [json.loads(line) for line in runtime.diagnostic_path.read_text(encoding="utf-8").splitlines()]
    assert records[-1]["phase"] == "rollback"
    assert "reload rejected" in records[-1]["error"]


def test_shutdown_cleans_owned_files_even_if_startup_never_created_process(tmp_path):
    runtime = object.__new__(IsolatedSuricataRuntime)
    runtime.process = None
    runtime.pidfile = tmp_path / "runtime" / "suricata.pid"
    runtime.socket_path = tmp_path / "runtime" / "suricata.sock"
    runtime.active_rules = tmp_path / "rules" / "active.rules"
    runtime.diagnostic_path = tmp_path / "logs" / "runtime-diagnostics.jsonl"
    for path in (runtime.pidfile, runtime.socket_path, runtime.active_rules):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("owned", encoding="utf-8")

    assert runtime.shutdown() is True
    assert not any(path.exists() for path in (runtime.pidfile, runtime.socket_path, runtime.active_rules))


def test_failed_frozen_attempt_records_failure_cleanup_rollback_and_production_state(
    monkeypatch, tmp_path,
):
    monkeypatch.setattr(operate_frozen_rst_once, "require_root_operator_if_supported", lambda: None)
    monkeypatch.setattr("netids.isolated_suricata_runtime.validate_unix_socket_path", lambda path: path)
    candidate = {"candidate_id": "c" * 64, "run_id": "g5-failure", "rule_sha256": "d" * 64}
    replay = {"probe_plan": [
        {"case": "A1", "label": "ATTACK", "scenario": "attack", "pcap_sha256": "a" * 64},
        {"case": "N1", "label": "NORMAL", "scenario": "normal", "pcap_sha256": "b" * 64},
    ]}
    owner = {
        "runtime_id": operate_frozen_rst_once.RUNTIME_ID,
        "target_vm": operate_frozen_rst_once.VM1_HOST,
        "interface": "lo",
        "isolated_root": str((tmp_path / "isolated").resolve()),
    }
    values = iter((candidate, replay, owner))
    audit_path = tmp_path / "isolated" / "audit" / "owner-once.jsonl"
    attempt_root = tmp_path / "isolated" / "attempts" / "attempt-02"
    (tmp_path / "isolated").mkdir()
    failure_path = attempt_root / "failure.json"
    runtime_diag = attempt_root / "runtime-diagnostics.jsonl"
    for name in ("replay.pub.pem", "owner.pub.pem", "runtime.pub.pem"):
        (tmp_path / name).write_bytes(b"test-key")

    class LifecycleProbe:
        def __init__(self, *args, **kwargs):
            pass

        def create_candidate(self, value):
            return value

        def transition(self, *_args):
            return None

        def record_validation(self, *_args):
            return None

        def approve(self, *_args):
            return None

        def stage(self, *_args, **_kwargs):
            raise OperationError("activation failure: reload rejected")

        def verify_audit(self):
            return 11

    class RuntimeProbe:
        def __init__(self, *args, **kwargs):
            attempt_root.mkdir(parents=True)
            runtime_diag.write_text(
                json.dumps({"phase": "reload", "status": "failed", "error": "socket rejected"}) + "\n",
                encoding="utf-8",
            )
            self.failure_phase = "reload"
            self.rollback_attempted = True
            self.rollback_verified = False
            self.post_rollback_verified = False
            self.diagnostic_path = runtime_diag
            self.attempt_root = attempt_root
            self.pidfile = attempt_root / "runtime.pid"
            self.socket_path = attempt_root / "runtime.sock"
            self.active_rules = attempt_root / "active.rules"
            self.process = SimpleNamespace(poll=lambda: 0)

        def shutdown(self):
            return True

    monkeypatch.setattr(operate_frozen_rst_once, "is_verified_vm1_host", lambda: True)
    monkeypatch.setattr(operate_frozen_rst_once, "_read_json", lambda _path: next(values))
    monkeypatch.setattr(operate_frozen_rst_once, "verify_frozen_candidate", lambda *args: {})
    monkeypatch.setattr(operate_frozen_rst_once, "verify_frozen_replay_attestation", lambda *args: True)
    monkeypatch.setattr(operate_frozen_rst_once, "verify_frozen_owner_authorization", lambda *args: True)
    monkeypatch.setattr(operate_frozen_rst_once, "_require_runtime_keypair", lambda *args: None)
    monkeypatch.setattr(operate_frozen_rst_once, "_require_candidate_baseline", lambda *args: None)
    probe_paths = [
        dict(replay["probe_plan"][0], path=tmp_path / "attack.pcap"),
        dict(replay["probe_plan"][1], path=tmp_path / "normal.pcap"),
    ]
    monkeypatch.setattr(operate_frozen_rst_once, "_probe_paths", lambda *args: probe_paths)
    monkeypatch.setattr(operate_frozen_rst_once, "production_snapshot", lambda *args, **kwargs: {"state": "same"})
    monkeypatch.setattr(operate_frozen_rst_once, "RuleLifecycle", LifecycleProbe)
    monkeypatch.setattr(operate_frozen_rst_once, "IsolatedSuricataRuntime", RuntimeProbe)

    with pytest.raises(OperationError, match="activation failure"):
        operate_frozen_rst_once.execute_frozen_once(
            candidate_file=tmp_path / "candidate.json",
            replay_file=tmp_path / "replay.json",
            owner_file=tmp_path / "owner.json",
            replay_public_file=tmp_path / "replay.pub.pem",
            owner_public_file=tmp_path / "owner.pub.pem",
            runtime_public_file=tmp_path / "runtime.pub.pem",
            production_yaml=tmp_path / "suricata.yaml",
            production_rules=tmp_path / "rules.rules",
            isolated_yaml=tmp_path / "isolated.yaml",
            isolated_root=tmp_path / "isolated",
            attempt_id="attempt-02",
            probe_specs=[], audit_path=audit_path, failure_path=failure_path,
            runtime_private_pem=b"private", runtime_private_password=b"password",
        )

    report = json.loads(failure_path.read_text(encoding="utf-8"))
    assert report["outcome"] == "FAILED"
    assert report["accepted"] is False
    assert report["failure_phase"] == "reload"
    assert report["rollback_status"] == "unverified"
    assert report["cleanup_status"] == "verified"
    assert report["production_state"] == "unchanged"
    assert report["lifecycle_audit_records"] == 11
    assert report["diagnostic_log_sha256"]
    assert report["attempt_id"] == "attempt-02"
    assert report["attempt_evidence_root"] == str((tmp_path / "isolated" / "attempts" / "attempt-02").resolve())


def test_isolated_runtime_records_probe_boundary_in_supplied_trace(monkeypatch, tmp_path):
    monkeypatch.setattr("netids.isolated_suricata_runtime.validate_unix_socket_path", lambda path: path)
    monkeypatch.setattr(IsolatedSuricataRuntime, "_preflight", lambda self: None)
    def fake_run(*args, **kwargs):
        (tmp_path / "logs" / "eve.json").write_text('{"event_type":"flow"}\n', encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="")
    monkeypatch.setattr("netids.isolated_suricata_runtime._run", fake_run)
    monkeypatch.setattr("netids.isolated_suricata_runtime.time.sleep", lambda seconds: None)
    pcap = tmp_path / "probe.pcap"
    pcap.write_bytes(b"synthetic-pcap")
    (tmp_path / "logs").mkdir()
    (tmp_path / "logs" / "eve.json").write_text("", encoding="utf-8")
    trace = LatencyTrace(run_id="g5-run", host="vm1", clock_sync={"status": "same_host_monotonic", "offset_ms": 0.0})
    runtime = IsolatedSuricataRuntime(
        config=tmp_path / "isolated.yaml",
        attack_pcap=pcap,
        attack_sha256="a" * 64,
        normal_pcap=pcap,
        normal_sha256="a" * 64,
        root=tmp_path,
        latency_trace=trace,
    )
    runtime._check_deadline = lambda: None
    assert runtime._pcap_probe(pcap, expect_alert=False, case="N1", label="NORMAL", scenario="normal") is True
    stages = trace.as_dict()["stages"]
    assert any(stage["name"] == "probe_active_N1" and stage["elapsed_ms"] >= 0 for stage in stages)


def test_isolated_runtime_trace_marks_false_operation_as_failed():
    runtime = object.__new__(IsolatedSuricataRuntime)
    runtime.latency_trace = LatencyTrace(run_id="g5-run", host="vm1", clock_sync={"status": "same_host_monotonic", "offset_ms": 0.0})
    assert runtime._measure_bool("activation", "runtime", lambda: False) is False
    stage = runtime.latency_trace.as_dict()["stages"][0]
    assert stage["status"] == "error"
    assert stage["error_type"] == "operation_returned_false"


def test_frozen_runtime_keypair_is_checked_before_lifecycle_side_effects(monkeypatch, tmp_path):
    monkeypatch.setattr(operate_frozen_rst_once, "require_root_operator_if_supported", lambda: None)
    monkeypatch.setattr("netids.isolated_suricata_runtime.validate_unix_socket_path", lambda path: path)
    _, runtime_public = generate_encrypted_keypair(b"runtime-test-password")
    (tmp_path / "isolated").mkdir()
    runtime_public_file = tmp_path / "runtime.pub.pem"
    runtime_public_file.write_bytes(runtime_public)
    (tmp_path / "replay.pub.pem").write_bytes(b"replay-public")
    (tmp_path / "owner.pub.pem").write_bytes(b"owner-public")
    candidate = {
        "run_id": "g5-run",
        "candidate_id": "candidate-id",
        "rule_sha256": "a" * 64,
        "rule_file_sha256": "b" * 64,
    }
    replay = {"probe_plan": []}
    owner = {
        "runtime_id": operate_frozen_rst_once.RUNTIME_ID,
        "target_vm": operate_frozen_rst_once.VM1_HOST,
        "interface": "lo",
        "isolated_root": str((tmp_path / "isolated").resolve()),
    }
    values = iter((candidate, replay, owner))
    lifecycle_created = []
    runtime_created = []
    activation_calls = []
    monkeypatch.setattr(operate_frozen_rst_once, "is_verified_vm1_host", lambda: True)
    monkeypatch.setattr(operate_frozen_rst_once, "_read_json", lambda _path: next(values))
    monkeypatch.setattr(operate_frozen_rst_once, "verify_frozen_candidate", lambda *args: {})
    monkeypatch.setattr(operate_frozen_rst_once, "verify_frozen_replay_attestation", lambda *args: True)
    monkeypatch.setattr(operate_frozen_rst_once, "verify_frozen_owner_authorization", lambda *args: True)
    monkeypatch.setattr(operate_frozen_rst_once, "production_snapshot", lambda *args, **kwargs: {"production_rules_sha256": "b" * 64})
    monkeypatch.setattr(operate_frozen_rst_once, "_require_candidate_baseline", lambda *args: None)
    monkeypatch.setattr(operate_frozen_rst_once, "_probe_paths", lambda *args: [])
    monkeypatch.setattr(
        operate_frozen_rst_once,
        "RuleLifecycle",
        lambda *args, **kwargs: lifecycle_created.append(True),
    )
    class RuntimeProbe:
        def __init__(self, *args, **kwargs):
            runtime_created.append(True)

        def activate(self, *args, **kwargs):
            activation_calls.append(True)

    monkeypatch.setattr(operate_frozen_rst_once, "IsolatedSuricataRuntime", RuntimeProbe)
    with pytest.raises(OperationError, match="runtime private/public key mismatch"):
        operate_frozen_rst_once.execute_frozen_once(
            candidate_file=tmp_path / "candidate.json",
            replay_file=tmp_path / "replay.json",
            owner_file=tmp_path / "owner.json",
            replay_public_file=tmp_path / "replay.pub.pem",
            owner_public_file=tmp_path / "owner.pub.pem",
            runtime_public_file=runtime_public_file,
            production_yaml=tmp_path / "suricata.yaml",
            production_rules=tmp_path / "rules.rules",
            isolated_yaml=tmp_path / "isolated.yaml",
            isolated_root=tmp_path / "isolated",
            attempt_id="attempt-keypair",
            probe_specs=[],
            audit_path=tmp_path / "isolated" / "audit" / "owner-once.jsonl",
            failure_path=tmp_path / "isolated" / "attempts" / "attempt-keypair" / "failure.json",
            runtime_private_pem=b"wrong-private-key",
            runtime_private_password=b"wrong-password",
        )
    assert lifecycle_created == []
    assert runtime_created == []
    assert activation_calls == []
    assert not (tmp_path / "isolated" / "audit" / "owner-once.jsonl").exists()
    assert not (tmp_path / "isolated" / "rules").exists()


def test_frozen_cli_forwards_exact_runtime_public_key_path(monkeypatch, tmp_path):
    monkeypatch.setattr("netids.isolated_suricata_runtime.validate_unix_socket_path", lambda path: path)
    (tmp_path / "isolated").mkdir()
    runtime_public_file = tmp_path / "keys" / "runtime.pub.pem"
    runtime_private_file = tmp_path / "keys" / "runtime.pem"
    runtime_public_file.parent.mkdir()
    runtime_public_file.write_bytes(b"runtime-public")
    runtime_private_file.write_bytes(b"test-private-placeholder")
    evidence_file = tmp_path / "isolated" / "attempts" / "attempt-cli" / "evidence.json"
    failure_file = tmp_path / "isolated" / "attempts" / "attempt-cli" / "failure.json"
    captured = {}

    def fake_execute_frozen_once(**kwargs):
        captured.update(kwargs)
        return {"outcome": "test"}

    monkeypatch.setattr(operate_frozen_rst_once, "execute_frozen_once", fake_execute_frozen_once)
    monkeypatch.setattr(operate_frozen_rst_once.getpass, "getpass", lambda _prompt: "test-password")

    assert operate_frozen_rst_once.main([
        "--candidate", str(tmp_path / "candidate.json"),
        "--replay", str(tmp_path / "replay.json"),
        "--owner-authorization", str(tmp_path / "owner.json"),
        "--replay-public", str(tmp_path / "replay.pub.pem"),
        "--owner-public", str(tmp_path / "owner.pub.pem"),
        "--runtime-public", str(runtime_public_file),
        "--production-yaml", str(tmp_path / "production.yaml"),
        "--production-rules", str(tmp_path / "production.rules"),
        "--isolated-yaml", str(tmp_path / "isolated.yaml"),
        "--isolated-root", str(tmp_path / "isolated"),
        "--attempt-id", "attempt-cli",
        "--audit-path", str(tmp_path / "isolated" / "audit" / "owner-once.jsonl"),
        "--runtime-private", str(runtime_private_file),
        "--evidence-output", str(evidence_file),
        "--failure-output", str(failure_file),
        "--probe", "ATTACK=/unused/attack.pcap",
    ]) == 0
    assert captured["runtime_public_file"] == runtime_public_file
