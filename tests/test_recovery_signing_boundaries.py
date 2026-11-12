import hashlib
import json

import pytest

import netids.lifecycle_integration as integration
from netids.lifecycle_integration import register_documented_frozen_candidate
from netids.trusted_replay import (
    DOCUMENTED_EVIDENCE_PATH, ReplayGateError, _create_exclusive_run_root,
)
from netids.rule_lifecycle import LifecycleError


def test_signing_run_is_additive_and_exclusive(tmp_path):
    root = tmp_path / "isolated-lifecycle-9103003"
    root.mkdir()
    old = root / "replay-evidence"
    old.mkdir()
    (old / "worker-attack-holdout-01-20261111").mkdir()
    marker = old / "worker-attack-holdout-01-20261111" / "eve.json"
    marker.write_text("prior-authentic-evidence\n", encoding="utf-8")

    fresh = _create_exclusive_run_root(root, "signing-01")
    assert fresh == old / "signed-signing-01"
    assert marker.read_text(encoding="utf-8") == "prior-authentic-evidence\n"
    with pytest.raises(ReplayGateError, match="already exists"):
        _create_exclusive_run_root(root, "signing-01")
    second = _create_exclusive_run_root(root, "signing-02")
    assert second != fresh
    assert marker.exists()


def _recovery_inputs(tmp_path, monkeypatch, *, bad_candidate=False):
    pcap_paths = []
    cases = {}
    for index, scenario in enumerate(("attack", "attack", "attack", "normal", "normal", "normal"), 1):
        path = tmp_path / f"holdout-{index}.pcap"
        path.write_bytes(f"immutable-pcap-{index}".encode())
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        identifier = f"case-{index}"
        cases[identifier] = (scenario, digest)
        pcap_paths.append(path)
    monkeypatch.setattr(integration, "EXPECTED_CASES", cases)
    run_id = "documented-recovery-test"
    candidate_id = hashlib.sha256(
        f"{run_id}:9103003:7182bb328ce4ed1230c6de9b20c825d458b8c224a494d6b2a60063cca5ec21df".encode()
    ).hexdigest()
    manifest = {
        "schema_version": "suricata_replay_manifest_v1",
        "candidate_id": "0" * 64 if bad_candidate else candidate_id,
        "run_id": run_id,
        "replay_run_id": "signing-test-01",
        "pcap_sha256": cases["case-1"][1],
        "sid": 9103003,
        "rule_sha256": "7182bb328ce4ed1230c6de9b20c825d458b8c224a494d6b2a60063cca5ec21df",
        "model_sha256": "206dadafc8d6cd96e21d838a52211d9b06d4a6ec541ea5c9a9ae8a6724ffbf5d",
        "calibration_sha256": "814e17006c5cfee433477128e9d29abf7e403e28948d78a968c46c800b67e060",
        "decision_manifest_sha256": "c7dffd3021d0c0195789e45c369f30108186753076b95586a2d80c9c744b579a",
        "cases": [
            {"id": key, "scenario": value[0], "pcap_path": str(pcap_paths[index]), "pcap_sha256": value[1]}
            for index, (key, value) in enumerate(cases.items())
        ],
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    return pcap_paths[0], manifest_path, hashlib.sha256(manifest_path.read_bytes()).hexdigest()


def test_documented_recovery_registration_is_review_only_and_bound(tmp_path, monkeypatch):
    source_pcap, manifest, manifest_sha = _recovery_inputs(tmp_path, monkeypatch)
    result = register_documented_frozen_candidate(
        repo_root=integration.Path(__file__).resolve().parents[1],
        evidence_path=integration.Path(DOCUMENTED_EVIDENCE_PATH),
        replay_manifest=manifest, expected_replay_manifest_sha256=manifest_sha,
        source_pcap=source_pcap,
        calibration_manifest=integration.Path("configs/hybrid_normal_calibration.json"),
        audit_path=tmp_path / "audit.jsonl", isolated_root=tmp_path / "isolated-lab",
    )
    assert result["status"] == "PROPOSED"
    assert result["evidence_class"] == "documented_frozen_rule_recovery"
    assert result["historical_generated_metadata"] == "unavailable_not_recovered"
    assert result["approved"] is result["deployable"] is result["deployed"] is False


def test_documented_recovery_rejects_forged_candidate_identity(tmp_path, monkeypatch):
    source_pcap, manifest, manifest_sha = _recovery_inputs(tmp_path, monkeypatch, bad_candidate=True)
    with pytest.raises(LifecycleError, match="candidate ID"):
        register_documented_frozen_candidate(
            repo_root=integration.Path(__file__).resolve().parents[1],
            evidence_path=integration.Path(DOCUMENTED_EVIDENCE_PATH),
            replay_manifest=manifest, expected_replay_manifest_sha256=manifest_sha,
            source_pcap=source_pcap,
            calibration_manifest=integration.Path("configs/hybrid_normal_calibration.json"),
            audit_path=tmp_path / "audit.jsonl", isolated_root=tmp_path / "isolated-lab",
        )
