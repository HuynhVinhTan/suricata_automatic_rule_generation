import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from netids.candidate_replay import CandidateReplayError, attest_candidate_replay
from netids.candidate_record import build_candidate_record, expected_candidate_runtime_id
from netids.lifecycle_ed25519 import generate_encrypted_keypair, verify_record
from scripts.approve_isolated_activation import build_candidate_owner_authorization
from tests.test_candidate_record import _fixture


PASSWORD = b"candidate-operational-test-password"


def _candidate(tmp_path):
    artifact, calibration, baseline = _fixture(tmp_path)
    return build_candidate_record(artifact, calibration, baseline), artifact, calibration, baseline


def _config(root: Path) -> Path:
    path = root / "isolated.yaml"
    path.write_text(
        "outputs:\n  - eve-log:\n      enabled: true\n      filename: eve.json\n",
        encoding="utf-8",
    )
    return path


def _manifest(tmp_path, candidate):
    cases = []
    for scenario, index in (("attack", 2), ("attack", 3), ("normal", 1), ("normal", 2), ("normal", 3)):
        pcap = tmp_path / f"{scenario}-{index}.pcap"
        pcap.write_bytes(f"{scenario}-{index}".encode())
        cases.append({
            "id": f"worker-{scenario}-holdout-{index}", "scenario": scenario,
            "pcap_path": str(pcap), "pcap_sha256": hashlib.sha256(pcap.read_bytes()).hexdigest(),
        })
    manifest = {
        "schema_version": "candidate_independent_replay_manifest_v1",
        "candidate_id": candidate["candidate_id"], "sid": candidate["sid"],
        "discovery_pcap_sha256": candidate["pcap_sha256"], "discovery_excluded": True,
        "minimum_attack_cases": 2, "minimum_normal_cases": 3, "cases": cases,
    }
    path = tmp_path / "independent-cases.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path, cases


def test_candidate_replay_signer_executes_gates_and_signs_only_fresh_eve(monkeypatch, tmp_path):
    candidate, artifact, calibration, baseline = _candidate(tmp_path)
    root = tmp_path / "isolated"
    root.mkdir()
    config = _config(root)
    manifest, cases = _manifest(tmp_path, candidate)
    def fake_run(argv, **kwargs):
        if "-r" in argv:
            logdir = Path(argv[argv.index("-l") + 1])
            is_attack = "attack" in str(argv)
            logdir.mkdir(parents=True, exist_ok=True)
            event = {"event_type": "alert", "alert": {"signature_id": 9103012}}
            if not is_attack:
                event = {"event_type": "flow", "flow": {"state": "established"}}
            (logdir / "eve.json").write_text(json.dumps(event) + "\n", encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="This is Suricata 8.0.3", stderr="")
    monkeypatch.setattr("netids.candidate_replay.subprocess.run", fake_run)
    private, public = generate_encrypted_keypair(PASSWORD)
    signed = attest_candidate_replay(
        candidate=candidate, artifact_dir=artifact, calibration_manifest=calibration,
        baseline_rules=baseline, case_manifest=manifest,
        expected_case_manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),
        isolated_yaml=config, isolated_root=root,
        private_key_pem=private, private_key_password=PASSWORD,
        replay_public_pem=public, suricata_binary="suricata",
    )
    assert verify_record(signed, public, domain="isolated-replay-v1")
    assert signed["sid"] == 9103012
    assert {case["scenario"] for case in signed["cases"]} == {"attack", "normal"}
    assert len(list((root / "replay-evidence" / "signing-runs").iterdir())) == 1


def test_candidate_replay_signer_rejects_discovery_case_before_suricata(monkeypatch, tmp_path):
    candidate, artifact, calibration, baseline = _candidate(tmp_path)
    root = tmp_path / "isolated"
    root.mkdir()
    config = _config(root)
    manifest, _ = _manifest(tmp_path, candidate)
    bad = json.loads(manifest.read_text(encoding="utf-8"))
    bad["cases"][0]["pcap_sha256"] = candidate["pcap_sha256"]
    manifest.write_text(json.dumps(bad), encoding="utf-8")
    called = []
    monkeypatch.setattr("netids.candidate_replay.subprocess.run", lambda *a, **k: called.append(a))
    with pytest.raises(CandidateReplayError, match="Discovery PCAP"):
        attest_candidate_replay(
            candidate=candidate, artifact_dir=artifact, calibration_manifest=calibration,
            baseline_rules=baseline, case_manifest=manifest,
            expected_case_manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),
            isolated_yaml=config, isolated_root=root, private_key_pem=b"", private_key_password=PASSWORD,
            replay_public_pem=b"", suricata_binary="suricata",
        )
    assert called == []


def test_candidate_owner_authorization_binds_runtime_and_replay(tmp_path):
    candidate, artifact, calibration, baseline = _candidate(tmp_path)
    replay_private, replay_public = generate_encrypted_keypair(PASSWORD)
    owner_private, owner_public = generate_encrypted_keypair(PASSWORD)
    replay = {
        "schema_version": "isolated_replay_attestation_v1",
        **{key: candidate[key] for key in ("candidate_id", "run_id", "sid", "rule_sha256", "pcap_sha256", "model_sha256", "calibration_sha256", "decision_manifest_sha256")},
        "suricata_version": "8.0.3", "syntax_authenticated": True,
        "attack_replay_passed": True, "normal_replay_passed": True,
        "normal_false_positive_count": 0, "threshold": 3,
        "case_manifest_schema": "candidate_independent_replay_manifest_v1",
        "case_manifest_sha256": "e" * 64,
        "minimum_attack_cases": 2, "minimum_normal_cases": 3,
        "experiment_id": "candidate-replay", "created_at": "2026-11-12T14:00:00+00:00",
        "cases": [
            {"run_id": "attack-independent", "scenario": "attack", "pcap_sha256": "1" * 64, "eve_sha256": "2" * 64, "events": 1, "candidate_sid_alerts": 1},
            {"run_id": "attack-independent-2", "scenario": "attack", "pcap_sha256": "3" * 64, "eve_sha256": "4" * 64, "events": 1, "candidate_sid_alerts": 1},
            {"run_id": "normal-independent", "scenario": "normal", "pcap_sha256": "5" * 64, "eve_sha256": "6" * 64, "events": 1, "candidate_sid_alerts": 0},
            {"run_id": "normal-independent-2", "scenario": "normal", "pcap_sha256": "7" * 64, "eve_sha256": "8" * 64, "events": 1, "candidate_sid_alerts": 0},
            {"run_id": "normal-independent-3", "scenario": "normal", "pcap_sha256": "9" * 64, "eve_sha256": "a" * 64, "events": 1, "candidate_sid_alerts": 0},
        ],
    }
    from netids.lifecycle_ed25519 import sign_record
    signed_replay = sign_record(replay, replay_private, PASSWORD, domain="isolated-replay-v1")
    isolated_root = "/isolated/9103012"
    runtime_id = expected_candidate_runtime_id(
        candidate, target_vm="suricata-vm1", interface="lo", isolated_root=isolated_root,
    )
    approval = build_candidate_owner_authorization(
        candidate, signed_replay, replay_public_pem=replay_public,
        owner_private_pem=owner_private, owner_private_password=PASSWORD,
        owner_public_pem=owner_public, approver_identity="owner@example.invalid",
        candidate_record_sha256="f" * 64, runtime_id=runtime_id,
        target_vm="suricata-vm1", interface="lo", isolated_root=isolated_root,
        nonce="a" * 32,
    )
    assert approval["sid"] == 9103012
    assert approval["runtime_id"] == runtime_id
    assert verify_record(approval, owner_public, domain="isolated-owner-approval-v1")
    with pytest.raises(ValueError, match="replay attestation"):
        build_candidate_owner_authorization(
            candidate, {**signed_replay, "sid": 9103003}, replay_public_pem=replay_public,
            owner_private_pem=owner_private, owner_private_password=PASSWORD,
            owner_public_pem=owner_public, approver_identity="owner@example.invalid",
            candidate_record_sha256="f" * 64, runtime_id=runtime_id,
            target_vm="suricata-vm1", interface="lo", isolated_root=isolated_root,
            nonce="b" * 32,
        )
