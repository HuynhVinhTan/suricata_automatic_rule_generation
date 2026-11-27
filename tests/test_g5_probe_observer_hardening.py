"""Synthetic PCAP and EVE tests for the frozen G5 probe observer."""

import hashlib
import json
import socket
import struct
import time as _time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from netids import isolated_suricata_runtime as observer
from netids.isolated_suricata_runtime import IsolatedSuricataRuntime


def _pcap_tcp(src="192.0.2.10", dst="192.0.2.20", sport=41000, dport=18100):
    tcp = struct.pack("!HHIIHHHH", sport, dport, 1, 0, 0x5002, 65535, 0, 0)
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0, 64, 6, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    )
    frame = b"\x00" * 12 + b"\x08\x00" + ip + tcp
    return (
        struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        + struct.pack("<IIII", 1, 0, len(frame), len(frame)) + frame
    )


def _event(event_type, *, timestamp=None, counters=(10, 10), flow_id=71,
           src_ip="192.0.2.10", dest_ip="192.0.2.20", src_port=41000,
           dest_port=18100, signature_id=None):
    record = {
        "event_type": event_type,
        "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
        "flow_id": flow_id,
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "src_port": src_port,
        "dest_port": dest_port,
        "proto": "TCP",
    }
    if event_type == "stats":
        record["stats"] = {
            "capture": {"kernel_packets": counters[0]},
            "decoder": {"pkts": counters[1]},
        }
    if event_type == "alert":
        record["alert"] = {"signature_id": signature_id or 9103005}
    return record


def _probe(tmp_path, monkeypatch, *, case="N1", label="NORMAL", records=(),
           timeout=0.03, slow_replay=0.0, global_deadline=None, replay_counters=(12, 12)):
    pcap = tmp_path / f"{case}.pcap"
    pcap.write_bytes(_pcap_tcp())
    digest = hashlib.sha256(pcap.read_bytes()).hexdigest()
    eve = tmp_path / "eve.json"
    baseline1 = _event("stats", timestamp=(datetime.now(timezone.utc) - timedelta(seconds=2)).isoformat())
    eve.write_text(json.dumps(baseline1) + "\n", encoding="utf-8")
    runtime = object.__new__(IsolatedSuricataRuntime)
    runtime.logdir = tmp_path
    runtime.tcpreplay = "tcpreplay"
    runtime.sid = 9103005
    runtime.deadline_monotonic = global_deadline
    runtime.probe_results = []
    runtime._last_attack_eve = ""
    runtime._check_deadline = lambda: None
    runtime.probe_plan = ({
        "case": case, "label": label, "scenario": "attack" if label == "ATTACK" else "normal",
        "pcap_sha256": digest, "path": pcap,
        "expected_alert": label == "ATTACK",
    },)
    monkeypatch.setattr(observer, "PROBE_OBSERVATION_SECONDS", timeout, raising=False)
    sleeps = {"count": 0}
    real_sleep = _time.sleep

    def fake_run(*_args, **_kwargs):
        if slow_replay:
            sleeps["clock"][0] += slow_replay
        # Stats emitted while replay is in progress do not close the post-replay
        # evidence window.
        with eve.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(_event("stats", counters=replay_counters)) + "\n")
        return SimpleNamespace(returncode=0, stdout="")

    def fake_sleep(seconds):
        sleeps["count"] += 1
        if "clock" in sleeps:
            sleeps["clock"][0] += min(seconds, 0.001) if seconds else 0.001
        else:
            real_sleep(min(seconds, 0.001))
        payload = records(sleeps["count"]) if callable(records) else records
        if payload:
            with eve.open("a", encoding="utf-8") as stream:
                for item in payload:
                    stream.write(json.dumps(item) + "\n")

    monkeypatch.setattr(observer, "_run", fake_run)
    monkeypatch.setattr(observer.time, "sleep", fake_sleep)
    if slow_replay:
        sleeps["clock"] = [0.0]
        monkeypatch.setattr(observer.time, "monotonic", lambda: sleeps["clock"][0])
        if global_deadline is not None:
            runtime.deadline_monotonic = 1.0
    return runtime, pcap, eve, sleeps


def test_global_stats_delta_without_matching_pcap_flow_fails(monkeypatch, tmp_path):
    runtime, pcap, _, _ = _probe(tmp_path, monkeypatch, timeout=0.01)
    assert runtime._pcap_probe_impl(pcap, expect_alert=False, case="N1", label="NORMAL") is False
    assert runtime.probe_results[-1]["traffic_proof"] is None


def test_latest_pre_replay_stats_record_is_the_baseline(monkeypatch, tmp_path):
    runtime, pcap, eve, _ = _probe(
        tmp_path, monkeypatch, replay_counters=(20, 20), timeout=0.01,
    )
    later_baseline = _event("stats", counters=(20, 20))
    with eve.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(later_baseline) + "\n")
    assert runtime._pcap_probe_impl(pcap, expect_alert=False, case="N1", label="NORMAL") is False
    result = runtime.probe_results[-1]
    assert result["counter_baseline"] == {"capture.kernel_packets": 20, "decoder.pkts": 20}
    assert result["counter_baseline_eve_offset"] > 0


def test_attack_waits_for_late_matching_flow_and_candidate_alert(monkeypatch, tmp_path):
    def delayed(count):
        if count == 1:
            return (_event("flow"), _event("stats", counters=(13, 13)))
        if count == 2:
            return (_event("alert", signature_id=9103005),)
        return ()

    runtime, pcap, _, sleeps = _probe(
        tmp_path, monkeypatch, case="A1", label="ATTACK", records=delayed,
    )
    assert runtime._pcap_probe_impl(pcap, expect_alert=True, case="A1", label="ATTACK") is True, runtime.probe_results[-1].get("failure_reason")
    assert sleeps["count"] >= 2
    assert runtime.probe_results[-1]["evidence_correlation_id"]


def test_normal_waits_full_window_and_fails_on_late_candidate_alert(monkeypatch, tmp_path):
    def delayed(count):
        if count == 1:
            return (_event("flow"), _event("stats", counters=(13, 13)))
        if count == 2:
            return (_event("alert", signature_id=9103005),)
        return ()

    runtime, pcap, _, sleeps = _probe(tmp_path, monkeypatch, records=delayed)
    assert runtime._pcap_probe_impl(pcap, expect_alert=False, case="N1", label="NORMAL") is False
    assert sleeps["count"] >= 2
    assert runtime.probe_results[-1]["failure_reason"] == "candidate_alert_expectation_mismatch"


def test_normal_passes_only_after_full_window_and_complete_tuple_proof(monkeypatch, tmp_path):
    runtime, pcap, _, sleeps = _probe(
        tmp_path, monkeypatch, records=lambda count: (_event("flow"), _event("stats", counters=(13, 13))) if count == 1 else (),
    )
    assert runtime._pcap_probe_impl(pcap, expect_alert=False, case="N1", label="NORMAL") is True, runtime.probe_results[-1].get("failure_reason")
    assert sleeps["count"] > 1
    assert runtime.probe_results[-1]["traffic_proof"]["matched_flow_count"] == 1


def test_wrong_flow_tuple_does_not_prove_probe_delivery(monkeypatch, tmp_path):
    runtime, pcap, _, _ = _probe(
        tmp_path, monkeypatch,
        records=lambda count: (_event("flow", src_port=49999), _event("stats", counters=(13, 13))) if count == 1 else (),
    )
    assert runtime._pcap_probe_impl(pcap, expect_alert=False, case="N1", label="NORMAL") is False


def test_candidate_alert_from_wrong_flow_fails_closed(monkeypatch, tmp_path):
    runtime, pcap, _, _ = _probe(
        tmp_path, monkeypatch, case="A1", label="ATTACK",
        records=lambda count: (_event("alert", src_port=49999), _event("flow"), _event("stats", counters=(13, 13))) if count == 1 else (),
    )
    assert runtime._pcap_probe_impl(pcap, expect_alert=True, case="A1", label="ATTACK") is False
    assert "unrelated" in runtime.probe_results[-1]["failure_reason"]


def test_alert_timestamp_outside_observation_window_is_ignored(monkeypatch, tmp_path):
    future = _event("alert", timestamp=(datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat())
    runtime, pcap, _, _ = _probe(
        tmp_path, monkeypatch,
        records=lambda count: (_event("flow"), _event("stats", counters=(13, 13)), future) if count == 1 else (),
    )
    assert runtime._pcap_probe_impl(pcap, expect_alert=False, case="N1", label="NORMAL") is True
    assert runtime.probe_results[-1]["candidate_alerts"] == 0


def test_slow_replay_gets_a_fresh_post_replay_window(monkeypatch, tmp_path):
    runtime, pcap, _, sleeps = _probe(
        tmp_path, monkeypatch, timeout=0.02, slow_replay=0.05,
        records=lambda count: (_event("flow"), _event("stats", counters=(13, 13))) if count == 1 else (),
        global_deadline=1.0,
    )
    assert runtime._pcap_probe_impl(pcap, expect_alert=False, case="N1", label="NORMAL") is True, runtime.probe_results[-1].get("failure_reason")
    assert runtime.probe_results[-1]["elapsed_ms"] >= 70
    assert sleeps["count"] > 1


def test_eve_tuple_must_be_from_signed_pcap_flow_set(monkeypatch, tmp_path):
    runtime, pcap, _, _ = _probe(
        tmp_path, monkeypatch,
        records=lambda count: (_event("flow"), _event("stats", counters=(13, 13))) if count == 1 else (),
    )
    digest = hashlib.sha256(pcap.read_bytes()).hexdigest()
    with pcap.open("ab") as stream:
        stream.write(b"tamper")
    assert runtime._pcap_probe_impl(pcap, expect_alert=False, case="N1", label="NORMAL") is False
    assert runtime.probe_results[-1]["pcap_sha256"] != digest
