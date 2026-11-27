import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from scripts.validate_g5_native_readiness import NativeReadinessError, validate_native_readiness
from scripts.validate_g5_startup_readiness import (
    StartupReadinessError, build_startup_command, require_startup_smoke_guard,
)


def _template(root: Path) -> Path:
    path = root / "isolated.yaml"
    path.write_text(
        "default-rule-path: ROOT/rules\n"
        "rule-files: [active.rules]\n"
        "unix-command: {enabled: true, filename: ROOT/runtime/lab-suricata.socket}\n"
        "af-packet: [{interface: lo}]\n"
        "outputs: [{eve-log: {enabled: true, filename: eve.json}}]\n".replace("ROOT", str(root)),
        encoding="utf-8",
    )
    return path


def test_native_readiness_uses_non_live_syntax_command_and_exact_paths(monkeypatch, tmp_path):
    monkeypatch.setattr("netids.isolated_suricata_runtime.validate_unix_socket_path", lambda path: path)
    monkeypatch.setattr("scripts.validate_g5_native_readiness.validate_unix_socket_path", lambda path: path)
    root = tmp_path / "isolated"
    root.mkdir()
    config = _template(root)
    candidate = root / "candidate.rules"
    candidate.write_text("alert tcp any any -> any any (sid:9103005; rev:1;)\n", encoding="utf-8")
    report = root / "readiness" / "attempt-readiness" / "readiness.json"
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout="This is Suricata version 8.0.3\n", stderr="")

    monkeypatch.setattr("scripts.validate_g5_native_readiness.subprocess.run", fake_run)

    result = validate_native_readiness(
        template_config=config,
        isolated_root=root,
        attempt_id="attempt-readiness",
        candidate_rules=candidate,
        suricata="suricata",
        report_path=report,
    )

    assert result["status"] == "READY_FOR_REVIEWED_AUTHORIZATION"
    assert len(calls) == 2
    assert calls[0][0] == ["suricata", "-V"]
    syntax = calls[1][0]
    assert "-T" in syntax and "-S" in syntax and "-r" not in syntax
    assert "--af-packet=lo" not in syntax
    assert syntax[syntax.index("-l") + 1] == str(root / "readiness" / "attempt-readiness" / "validation-logs")
    assert calls[1][1]["cwd"] == root / "readiness" / "attempt-readiness"
    effective = yaml.safe_load(Path(result["effective_config"]).read_text(encoding="utf-8"))
    assert Path(result["effective_config"]).read_bytes().startswith(b"%YAML 1.1\n---\n")
    assert effective["rule-files"] == ["active.rules"]
    assert effective["af-packet"] == [{"interface": "lo"}]
    assert Path(effective["default-rule-path"]).is_relative_to(root / "readiness" / "attempt-readiness")
    assert Path(effective["unix-command"]["filename"]).is_relative_to(root / "readiness" / "attempt-readiness")
    assert json.loads(report.read_text(encoding="utf-8"))["status"] == result["status"]


def test_native_readiness_refuses_reused_attempt_and_production_rule_paths(monkeypatch, tmp_path):
    monkeypatch.setattr("netids.isolated_suricata_runtime.validate_unix_socket_path", lambda path: path)
    monkeypatch.setattr("scripts.validate_g5_native_readiness.validate_unix_socket_path", lambda path: path)
    root = tmp_path / "isolated"
    root.mkdir()
    config = _template(root)
    candidate = root / "candidate.rules"
    candidate.write_text("alert tcp any any -> any any (sid:9103005; rev:1;)\n", encoding="utf-8")
    (root / "attempts" / "attempt-reused").mkdir(parents=True)
    with pytest.raises(NativeReadinessError, match="evidence namespace"):
        validate_native_readiness(
            template_config=config,
            isolated_root=root,
            attempt_id="attempt-reused",
            candidate_rules=candidate,
            suricata="suricata",
        )
    with pytest.raises(NativeReadinessError, match="production"):
        validate_native_readiness(
            template_config=config, isolated_root=root, attempt_id="attempt-production",
            candidate_rules=Path("/etc/suricata/rules/suricata.rules"), suricata="suricata",
        )


def test_native_readiness_rejects_logging_output_escape(monkeypatch, tmp_path):
    monkeypatch.setattr("netids.isolated_suricata_runtime.validate_unix_socket_path", lambda path: path)
    monkeypatch.setattr("scripts.validate_g5_native_readiness.validate_unix_socket_path", lambda path: path)
    root = tmp_path / "isolated"
    root.mkdir()
    config = _template(root)
    config.write_text(
        config.read_text(encoding="utf-8")
        + "logging:\n  outputs:\n    - file:\n        enabled: true\n        filename: ../outside.log\n",
        encoding="utf-8",
    )
    candidate = root / "candidate.rules"
    candidate.write_text("alert tcp any any -> any any (sid:9103005; rev:1;)\n", encoding="utf-8")
    with pytest.raises(NativeReadinessError, match="output path"):
        validate_native_readiness(
            template_config=config, isolated_root=root, attempt_id="attempt-unsafe-output",
            candidate_rules=candidate, suricata="suricata",
        )


def test_startup_readiness_requires_explicit_guard():
    with pytest.raises(StartupReadinessError, match="explicit startup smoke guard"):
        require_startup_smoke_guard([], {})


def test_startup_readiness_command_is_empty_ruleset_and_no_replay(tmp_path):
    command = build_startup_command(
        suricata="suricata",
        config=tmp_path / "suricata.yaml",
        logs=tmp_path / "logs",
        pidfile=tmp_path / "runtime" / "suricata.pid",
        service_user="suricata-g5",
        service_group="suricata-g5",
    )
    assert "--af-packet=lo" in command
    assert "-S" not in command and "-s" not in command
    assert "tcpreplay" not in command
    assert "--user=suricata-g5" in command
    assert "--group=suricata-g5" in command
