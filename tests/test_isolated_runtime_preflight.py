"""Isolated runtime fail-closed preflight tests: never start Suricata in CI."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from netids.isolated_suricata_runtime import (
    IsolatedSuricataRuntime, IsolatedRuntimeError, is_verified_vm1_host,
)
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
