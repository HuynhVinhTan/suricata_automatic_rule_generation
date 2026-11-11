"""Isolated runtime fail-closed preflight tests: never start Suricata in CI."""

from pathlib import Path

import pytest

from netids.isolated_suricata_runtime import IsolatedSuricataRuntime, IsolatedRuntimeError
from scripts.operate_isolated_once import OperationError, production_snapshot


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
        "scripts.operate_isolated_once.socket.gethostname",
        lambda: "suricata-vm1",
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
