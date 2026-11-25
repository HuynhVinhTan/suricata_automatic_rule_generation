"""Isolated runtime fail-closed preflight tests: never start Suricata in CI."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from netids.isolated_suricata_runtime import (
    IsolatedSuricataRuntime, IsolatedRuntimeError, is_verified_vm1_host,
)
from netids.latency import LatencyTrace
from scripts.operate_isolated_once import (
    OperationError, _require_candidate_baseline, production_snapshot,
)


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


def test_candidate_baseline_must_match_actual_production_rules_hash():
    candidate = {"baseline_rules_sha256": "a" * 64}
    snapshot = {"production_rules_sha256": "a" * 64}
    _require_candidate_baseline(candidate, snapshot)
    with pytest.raises(OperationError, match="baseline rules"):
        _require_candidate_baseline(candidate, {"production_rules_sha256": "b" * 64})


def test_candidate_baseline_missing_hash_fails_closed():
    with pytest.raises(OperationError, match="baseline rules"):
        _require_candidate_baseline({}, {"production_rules_sha256": "a" * 64})


def test_isolated_runtime_records_probe_boundary_in_supplied_trace(monkeypatch, tmp_path):
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
