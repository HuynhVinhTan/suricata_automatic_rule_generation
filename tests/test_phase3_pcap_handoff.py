"""Offline contract tests: no SSH, production Suricata, models or ELK."""
import hashlib
import json
import os
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest

import backend
from backend import pcap_handoff as bridge


SRC = "192.168.10.20"
DST = "192.168.10.10"


def _packet(flags: int, payload: bytes = b"") -> bytes:
    ip_src = bytes((192, 168, 10, 20))
    ip_dst = bytes((192, 168, 10, 10))
    tcp = struct.pack(
        "!HHIIBBHHH", 50000, 18100, 1, 0, 0x50, flags, 8192, 0, 0
    ) + payload
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0x4000, 64, 6, 0, ip_src, ip_dst
    )
    return b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x00" + ip + tcp


def _raw_pcap(frames: list[bytes]) -> bytes:
    pcap = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
    for idx, frame in enumerate(frames):
        pcap += struct.pack("<IIII", idx + 1, 0, len(frame), len(frame))
        pcap += frame
    return bytes(pcap)


def _prepared(tmp_path: Path):
    input_root = tmp_path / "capture"
    outbox = tmp_path / "outbox"
    private = tmp_path / "private"
    inbox = tmp_path / "inbox"
    for folder in (input_root, outbox, private, inbox):
        folder.mkdir()
    file = input_root / "sample.pcap"
    file.write_bytes(_raw_pcap([
        _packet(0x02),
        _packet(0x18, b"GET /admin HTTP/1.1\r\nHost: lab\r\n\r\n"),
    ]))
    expected = hashlib.sha256(file.read_bytes()).hexdigest()
    opts = dict(
        pcap=file,
        input_root=input_root,
        outbox=outbox,
        run_id="lab-001",
        src=SRC,
        dst=DST,
        expected_sha256=expected,
        expected_syn=1,
        expected_get=1,
    )
    return opts, inbox, private


def _copy_bundle(outbox: Path, inbox: Path, run_id: str = "lab-001"):
    folder = outbox / run_id
    for file in folder.iterdir():
        (inbox / file.name).write_bytes(file.read_bytes())


def _create_bundle(opts, run_id):
    bridge.bundle(**{**opts, "run_id": run_id})


def test_seal_and_receive_dry_run_are_verified(tmp_path):
    opts, inbox, private = _prepared(tmp_path)
    before = opts["pcap"].read_bytes()
    result = bridge.bundle(**opts)
    assert result["packets"] == 2
    assert result["initial_syn"] == 1
    assert result["http_get_starts"] == 1
    assert opts["pcap"].read_bytes() == before
    p, m, r, doc = bridge.verified_bundle(opts["outbox"] / "lab-001", "lab-001")
    assert p.read_bytes() == before
    assert json.loads(m.read_text())["source_ipv4"] == SRC
    assert r.exists()
    assert doc["capture_metadata"]["capture_kind"] == "raw"
    _copy_bundle(opts["outbox"], inbox)
    assert bridge.consume(
        input_root=inbox, private_root=private, run_id="lab-001", execute=False
    )["status"] == "validated_dry_run"
    assert not (inbox / "lab-001.done.json").exists()
    with pytest.raises(FileExistsError):
        bridge.bundle(**opts)


def test_expected_count_gate_fails_before_creating_bundle(tmp_path):
    opts, _, _ = _prepared(tmp_path)
    opts["expected_syn"] = 96
    with pytest.raises(bridge.HandoffError, match="count"):
        bridge.bundle(**opts)
    assert not (opts["outbox"] / "lab-001").exists()


def test_wrong_sha_rejects_without_side_effect(tmp_path):
    opts, _, _ = _prepared(tmp_path)
    opts["expected_sha256"] = "f" * 64
    with pytest.raises(bridge.HandoffError, match="SHA256"):
        bridge.bundle(**opts)
    assert not (opts["outbox"] / "lab-001").exists()


def test_truncated_record_rejected(tmp_path):
    opts, _, _ = _prepared(tmp_path)
    raw = bytearray(opts["pcap"].read_bytes())
    count = struct.unpack_from("<I", raw, 24 + 8)[0]
    struct.pack_into("<I", raw, 24 + 12, count + 1)
    opts["pcap"].write_bytes(raw)
    opts["expected_sha256"] = hashlib.sha256(raw).hexdigest()
    with pytest.raises(bridge.HandoffError, match="Truncated"):
        bridge.bundle(**opts)


def test_partial_last_record_rejected(tmp_path):
    opts, _, _ = _prepared(tmp_path)
    raw = opts["pcap"].read_bytes()[:-1]
    opts["pcap"].write_bytes(raw)
    opts["expected_sha256"] = hashlib.sha256(raw).hexdigest()
    with pytest.raises(bridge.HandoffError, match="Incomplete"):
        bridge.bundle(**opts)


def test_symlink_input_rejected(tmp_path):
    opts, _, _ = _prepared(tmp_path)
    link = opts["input_root"] / "link.pcap"
    try:
        link.symlink_to(opts["pcap"])
    except OSError:
        pytest.skip("Symlinks unavailable")
    opts["pcap"] = link
    with pytest.raises(bridge.HandoffError, match="symlink"):
        bridge.bundle(**opts)


def test_tampered_manifest_and_ready_fail_closed(tmp_path):
    opts, inbox, private = _prepared(tmp_path)
    bridge.bundle(**opts)
    _copy_bundle(opts["outbox"], inbox)
    manifest = inbox / "lab-001.manifest.json"
    data = json.loads(manifest.read_text())
    data["source_ipv4"] = "203.0.113.7"
    manifest.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(bridge.HandoffError, match="checksum"):
        bridge.consume(
            input_root=inbox, private_root=private, run_id="lab-001", execute=False
        )


def test_transfer_dry_run_never_invokes_ssh(tmp_path, monkeypatch):
    opts, _, _ = _prepared(tmp_path)
    bridge.bundle(**opts)
    def no_ssh(*args, **kwargs):
        raise AssertionError("No external commands during dry-run")
    monkeypatch.setattr(bridge.subprocess, "run", no_ssh)
    result = bridge.send(
        outbox=opts["outbox"], run_id="lab-001",
        remote_user="tanhv", remote_host="192.168.10.30",
        remote_inbox="/home/tanhv/ai-inbox", execute=False,
    )
    assert result["status"] == "validated_dry_run"
    with pytest.raises(ValueError):
        bridge.send(
            outbox=opts["outbox"], run_id="lab-001",
            remote_user="tanhv", remote_host="192.168.10.30",
            remote_inbox="/home/tanhv/../../etc", execute=True,
        )
    with pytest.raises(bridge.HandoffError, match="designated lab VM3"):
        bridge.send(
            outbox=opts["outbox"], run_id="lab-001",
            remote_user="tanhv", remote_host="192.168.10.99",
            remote_inbox="/home/tanhv/ai-inbox", execute=True,
        )


def test_transfer_publishes_ready_last_with_strict_ssh(tmp_path, monkeypatch):
    opts, _, _ = _prepared(tmp_path)
    bridge.bundle(**opts)
    commands = []
    def fake_run(command, **kwargs):
        commands.append(command)
        assert kwargs["check"] is True
        assert "StrictHostKeyChecking=yes" in command
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(bridge.subprocess, "run", fake_run)
    assert bridge.send(
        outbox=opts["outbox"], run_id="lab-001",
        remote_user="tanhv", remote_host="192.168.10.30",
        remote_inbox="/home/tanhv/ai-inbox", execute=True,
    )["status"] == "transferred"
    assert len(commands) == 5  # SSH preflight, three staged scp files, SSH finalize
    assert commands[-1][-1].count("ln -T -- ") == 3
    assert commands[-1][-1].index("ln -T -- /home/tanhv/ai-inbox/lab-001.pcap.partial") < commands[-1][-1].index("ln -T -- /home/tanhv/ai-inbox/lab-001.ready.json.partial")
    assert all(".partial" in commands[i][-1] for i in (1, 2, 3))


def test_receiver_execute_and_idempotent_receipt(tmp_path, monkeypatch):
    opts, inbox, private = _prepared(tmp_path)
    bridge.bundle(**opts)
    _copy_bundle(opts["outbox"], inbox)
    calls = []
    def fake_worker(**kwargs):
        calls.append(kwargs)
        assert kwargs["run_id"] == "lab-001"
        folder = kwargs["private_root"] / "lab-runs" / "lab-001"
        folder.mkdir(parents=True)
        summary = {
            "schema_version": bridge.WORKER_SCHEMA,
            "run_id": "lab-001",
            "status": "succeeded",
            "review_status": "needs_review",
            "pcap_sha256": hashlib.sha256(kwargs["pcap"].read_bytes()).hexdigest(),
            "model_sha256": "a" * 64,
            "deployable": False,
            "deployed": False,
            "rule_generated_in_this_run": False,
            "windows": 1,
            "isolation_forest_flagged": 0,
            "autoencoder_flagged": 0,
            "both_flagged": 0,
        }
        (folder / "worker_summary.json").write_text(json.dumps(summary))
        return summary
    def verify_completed_run(private_root, run_id, pcap_sha256):
        summary_path = private_root / "lab-runs" / run_id / "worker_summary.json"
        summary = json.loads(summary_path.read_text())
        if (
            summary.get("pcap_sha256") != pcap_sha256
            or summary.get("deployable") is not False
            or summary.get("deployed") is not False
        ):
            raise bridge.HandoffError("summary identity or safety mismatch")
        return summary
    monkeypatch.setattr(
        backend, "worker",
        SimpleNamespace(run_worker=fake_worker,
                        verify_completed_run=verify_completed_run,
                        write_elasticsearch_summary=lambda *_: None),
        raising=False,
    )
    result = bridge.consume(
        input_root=inbox, private_root=private, run_id="lab-001", execute=True
    )
    assert result["status"] == "processed"
    assert len(calls) == 1
    assert (inbox / "lab-001.done.json").exists()
    assert bridge.consume(
        input_root=inbox, private_root=private, run_id="lab-001", execute=True
    )["status"] == "already_processed"
    assert len(calls) == 1
    # A receipt cannot hide tampered worker provenance.
    report = private / "lab-runs" / "lab-001" / "worker_summary.json"
    report.write_text('{"status":"succeeded","pcap_sha256":"tampered"}')
    with pytest.raises(bridge.HandoffError, match="summary"):
        bridge.consume(
            input_root=inbox, private_root=private, run_id="lab-001", execute=True
        )


def test_failed_index_does_not_claim_completion(tmp_path, monkeypatch):
    opts, inbox, private = _prepared(tmp_path)
    bridge.bundle(**opts)
    _copy_bundle(opts["outbox"], inbox)
    calls = []
    def fake_worker(**kwargs):
        calls.append(kwargs)
        folder = kwargs["private_root"] / "lab-runs" / "lab-001"
        folder.mkdir(parents=True)
        summary = {
            "schema_version": bridge.WORKER_SCHEMA,
            "run_id": "lab-001",
            "status": "succeeded",
            "review_status": "needs_review",
            "pcap_sha256": hashlib.sha256(kwargs["pcap"].read_bytes()).hexdigest(),
            "model_sha256": "a" * 64,
            "deployable": False,
            "deployed": False,
            "rule_generated_in_this_run": False,
            "windows": 1,
            "isolation_forest_flagged": 0,
            "autoencoder_flagged": 0,
            "both_flagged": 0,
        }
        (folder / "worker_summary.json").write_text(json.dumps(summary))
        return summary
    def verify_completed_run(private_root, run_id, pcap_sha256):
        summary = json.loads(
            (private_root / "lab-runs" / run_id / "worker_summary.json").read_text()
        )
        assert summary["pcap_sha256"] == pcap_sha256
        return summary
    def failed_index(*args):
        raise RuntimeError("Elasticsearch unavailable")
    monkeypatch.setattr(
        backend, "worker",
        SimpleNamespace(run_worker=fake_worker,
                        verify_completed_run=verify_completed_run,
                        write_elasticsearch_summary=failed_index),
        raising=False,
    )
    with pytest.raises(RuntimeError):
        bridge.consume(
            input_root=inbox, private_root=private, run_id="lab-001",
            execute=True, elasticsearch_url="http://127.0.0.1:9200"
        )
    assert not (inbox / "lab-001.done.json").exists()
    summary_path = private / "lab-runs" / "lab-001" / "worker_summary.json"
    previous_summary = summary_path.read_bytes()

    publishes = []
    def recovered_index(summary, url):
        publishes.append((summary, url))
    monkeypatch.setattr(
        backend, "worker",
        SimpleNamespace(run_worker=fake_worker,
                        verify_completed_run=verify_completed_run,
                        write_elasticsearch_summary=recovered_index),
        raising=False,
    )
    assert bridge.consume(
        input_root=inbox, private_root=private, run_id="lab-001",
        execute=True, elasticsearch_url="http://127.0.0.1:9200"
    )["status"] == "recovered"
    assert len(calls) == 1
    assert len(publishes) == 1
    assert summary_path.read_bytes() == previous_summary
    done = json.loads((inbox / "lab-001.done.json").read_text())
    assert done["summary_sha256"] == hashlib.sha256(previous_summary).hexdigest()


def test_send_all_ready_counts_pending_not_historical(tmp_path, monkeypatch, capsys):
    opts, _, _ = _prepared(tmp_path)
    run_ids = [f"lab-{index:02d}" for index in range(1, 14)]
    for run_id in run_ids:
        _create_bundle(opts, run_id)
    for run_id in run_ids[:11]:
        ready = opts["outbox"] / run_id / f"{run_id}.ready.json"
        (opts["outbox"] / run_id / f"{run_id}.sent.json").write_text(json.dumps({
            "status": "sent",
            "run_id": run_id,
            "ready_sha256": hashlib.sha256(ready.read_bytes()).hexdigest(),
            "remote": "tanhv@192.168.10.30",
            "remote_inbox": "/home/tanhv/ai-inbox",
            "sent_at": "2026-11-10T00:00:00+00:00",
        }))
    selected = []
    monkeypatch.setattr(
        bridge, "send",
        lambda **kwargs: selected.append(kwargs["run_id"]) or {"status": "dry"},
    )
    assert bridge.main([
        "send", "--outbox", str(opts["outbox"]), "--all-ready",
        "--remote-user", "tanhv", "--remote-host", "192.168.10.30",
        "--remote-inbox", "/home/tanhv/ai-inbox",
    ]) == 0
    assert selected == run_ids[11:]
    assert json.loads(capsys.readouterr().out)[0]["status"] == "dry"


def test_send_all_ready_fails_on_invalid_historical_receipt(
    tmp_path, monkeypatch, capsys
):
    opts, _, _ = _prepared(tmp_path)
    _create_bundle(opts, "lab-old")
    receipt = opts["outbox"] / "lab-old" / "lab-old.sent.json"
    receipt.write_text(json.dumps({
        "status": "sent",
        "run_id": "lab-old",
        "ready_sha256": "0" * 64,
        "remote": "tanhv@192.168.10.30",
        "remote_inbox": "/home/tanhv/ai-inbox",
    }))
    called = []
    monkeypatch.setattr(bridge, "send", lambda **kwargs: called.append(kwargs))
    assert bridge.main([
        "send", "--outbox", str(opts["outbox"]), "--all-ready",
        "--remote-user", "tanhv", "--remote-host", "192.168.10.30",
        "--remote-inbox", "/home/tanhv/ai-inbox",
    ]) == 1
    assert called == []
    assert json.loads(capsys.readouterr().out)["status"] == "failed"


def test_send_all_ready_limits_pending_runs_to_ten(tmp_path, monkeypatch):
    opts, _, _ = _prepared(tmp_path)
    run_ids = [f"pending-{index:02d}" for index in range(12)]
    for run_id in run_ids:
        _create_bundle(opts, run_id)
    selected = []
    monkeypatch.setattr(
        bridge, "send",
        lambda **kwargs: selected.append(kwargs["run_id"]) or {"status": "dry"},
    )
    assert bridge.main([
        "send", "--outbox", str(opts["outbox"]), "--all-ready",
        "--remote-user", "tanhv", "--remote-host", "192.168.10.30",
        "--remote-inbox", "/home/tanhv/ai-inbox",
    ]) == 0
    assert selected == run_ids[:10]


def test_consume_all_ready_skips_valid_history_and_caps_pending(
    tmp_path, monkeypatch, capsys
):
    opts, inbox, private = _prepared(tmp_path)
    historical = [f"done-{index:02d}" for index in range(11)]
    pending = [f"todo-{index:02d}" for index in range(12)]
    run_ids = historical + pending
    for run_id in run_ids:
        _create_bundle(opts, run_id)
        _copy_bundle(opts["outbox"], inbox, run_id)
    summaries = {}
    for run_id in historical:
        output = private / "lab-runs" / run_id
        output.mkdir(parents=True)
        summary = {
            "schema_version": bridge.WORKER_SCHEMA,
            "run_id": run_id,
            "status": "succeeded",
            "review_status": "needs_review",
            "pcap_sha256": json.loads(
                (inbox / f"{run_id}.manifest.json").read_text()
            )["pcap_sha256"],
            "deployable": False,
            "deployed": False,
        }
        summaries[run_id] = summary
        summary_path = output / "worker_summary.json"
        summary_path.write_text(json.dumps(summary))
        (inbox / f"{run_id}.done.json").write_text(json.dumps({
            "run_id": run_id,
            "pcap_sha256": summary["pcap_sha256"],
            "summary_sha256": hashlib.sha256(summary_path.read_bytes()).hexdigest(),
            "status": "succeeded",
            "completed_at": "2026-11-10T00:00:00+00:00",
        }))
    monkeypatch.setattr(
        backend, "worker",
        SimpleNamespace(verify_completed_run=lambda root, run_id, sha: summaries[run_id]),
        raising=False,
    )
    selected = []
    monkeypatch.setattr(
        bridge, "consume",
        lambda **kwargs: selected.append(kwargs["run_id"]) or {"status": "dry"},
    )
    assert bridge.main([
        "consume", "--input-root", str(inbox), "--private-root", str(private),
        "--all-ready",
    ]) == 0
    assert selected == pending[:10]
    assert json.loads(capsys.readouterr().out) == [{"status": "dry"}] * 10


def test_consume_all_ready_fails_on_invalid_done_receipt(
    tmp_path, monkeypatch, capsys
):
    opts, inbox, private = _prepared(tmp_path)
    _create_bundle(opts, "lab-done")
    _copy_bundle(opts["outbox"], inbox, "lab-done")
    (inbox / "lab-done.done.json").write_text("{}")
    selected = []
    monkeypatch.setattr(bridge, "consume", lambda **kwargs: selected.append(kwargs))
    assert bridge.main([
        "consume", "--input-root", str(inbox), "--private-root", str(private),
        "--all-ready",
    ]) == 1
    assert selected == []
    assert json.loads(capsys.readouterr().out)["status"] == "failed"
