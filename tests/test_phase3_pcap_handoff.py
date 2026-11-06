"""Offline contract tests: no SSH, production Suricata, models or ELK."""
import hashlib
import json
import os
import struct
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

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
        (folder / "worker_summary.json").write_text('{"status":"succeeded"}')
        return {"review_status": "needs_review"}
    monkeypatch.setitem(
        sys.modules, "backend.worker",
        SimpleNamespace(run_worker=fake_worker,
                        write_elasticsearch_summary=lambda *_: None)
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


def test_failed_index_does_not_claim_completion(tmp_path, monkeypatch):
    opts, inbox, private = _prepared(tmp_path)
    bridge.bundle(**opts)
    _copy_bundle(opts["outbox"], inbox)
    def fake_worker(**kwargs):
        return {"review_status": "needs_review"}
    def failed_index(*args):
        raise RuntimeError("Elasticsearch unavailable")
    monkeypatch.setitem(
        sys.modules, "backend.worker",
        SimpleNamespace(run_worker=fake_worker,
                        write_elasticsearch_summary=failed_index)
    )
    with pytest.raises(RuntimeError):
        bridge.consume(
            input_root=inbox, private_root=private, run_id="lab-001",
            execute=True, elasticsearch_url="http://127.0.0.1:9200"
        )
    assert not (inbox / "lab-001.done.json").exists()
