import hashlib
import json

import pytest

from backend import rule_handoff


def _artifact(tmp_path):
    rule = 'alert tcp any any -> 192.0.2.10 any (msg:"test"; sid:9103000; rev:1;)'
    (tmp_path / "ml-generated.rules").write_text(rule + "\n", encoding="utf-8")
    rule_sha = hashlib.sha256(rule.encode()).hexdigest()
    (tmp_path / "ml-generated.metadata.json").write_text(
        json.dumps({
            "schema_version": "ml_rule_metadata_v1",
            "run_id": "recon-001",
            "pcap_sha256": "a" * 64,
            "model_sha256": "b" * 64,
            "rule_sha256": rule_sha,
            "approved": False,
            "deployable": False,
            "deployed": False,
            "status": "needs_review",
        }),
        encoding="utf-8",
    )


def test_transfer_requires_explicit_approval_for_execution(tmp_path):
    _artifact(tmp_path)
    with pytest.raises(rule_handoff.HandoffError, match="approval"):
        rule_handoff.send(
            artifact_dir=tmp_path,
            run_id="recon-001",
            execute=True,
            approve=False,
        )


def test_dry_run_validates_artifact_without_network(tmp_path, monkeypatch):
    _artifact(tmp_path)
    monkeypatch.setattr(
        rule_handoff.subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("network")),
    )
    result = rule_handoff.send(
        artifact_dir=tmp_path,
        run_id="recon-001",
        execute=False,
        approve=False,
    )
    assert result["status"] == "validated_dry_run"


def test_transfer_uses_pinned_alias_and_atomic_non_overwrite(tmp_path, monkeypatch):
    _artifact(tmp_path)
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)

    monkeypatch.setattr(rule_handoff.subprocess, "run", fake_run)
    result = rule_handoff.send(
        artifact_dir=tmp_path,
        run_id="recon-001",
        execute=True,
        approve=True,
    )

    assert result["status"] == "sent"
    assert len(calls) == 4
    flat = " ".join(" ".join(command) for command in calls)
    assert "suricata-vm1" in flat
    assert "StrictHostKeyChecking=yes" in flat
    assert "UserKnownHostsFile" in flat
    assert ".partial" in flat
    assert "mv --no-target-directory" in flat
    assert "test ! -e" in flat
