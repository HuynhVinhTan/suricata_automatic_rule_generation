import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import netids.candidate_replay as candidate_replay
import netids.candidate_record as candidate_record
import netids.key_pins as key_pins
from netids.candidate_replay import (
    APPROVED_CASE_MANIFEST_SHA256, CandidateReplayError, attest_candidate_replay,
    _validate_isolated_root, resolve_manifest_pcap_path,
)
from netids.candidate_record import (
    APPROVED_INDEPENDENT_CASES, build_candidate_record, expected_candidate_runtime_id,
)
from netids.lifecycle_ed25519 import generate_encrypted_keypair, public_key_fingerprint, verify_record
from scripts.approve_isolated_activation import build_candidate_owner_authorization
from scripts.operate_isolated_once import OperationError, _write_failure_report
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
        pcap = tmp_path / "fresh-holdouts-20261111" / f"{scenario}-holdout-{index}" / "traffic.pcap"
        pcap.parent.mkdir(parents=True, exist_ok=True)
        pcap.write_bytes(f"{scenario}-{index}".encode())
        cases.append({
            "id": f"worker-{scenario}-holdout-{index}", "scenario": scenario,
            "pcap_path": f"data/private/fresh-holdouts-20261111/{scenario}-holdout-{index}/traffic.pcap",
            "pcap_sha256": hashlib.sha256(pcap.read_bytes()).hexdigest(),
        })
    manifest = {
        "schema_version": "candidate_independent_replay_manifest_v1",
        "candidate_id": candidate["candidate_id"], "sid": candidate["sid"],
        "discovery_pcap_sha256": candidate["pcap_sha256"], "discovery_excluded": True,
        "minimum_attack_cases": 2, "minimum_normal_cases": 3, "cases": cases,
    }
    path = tmp_path / "independent-cases.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path, cases, tmp_path / "fresh-holdouts-20261111"


def test_candidate_replay_signer_executes_gates_and_signs_only_fresh_eve(monkeypatch, tmp_path):
    candidate, artifact, calibration, baseline = _candidate(tmp_path)
    root = tmp_path / "isolated-candidate-9103012"
    root.mkdir()
    monkeypatch.setattr(candidate_replay, "APPROVED_VM1_ISOLATED_WORKSPACE", tmp_path)
    config = _config(root)
    manifest, cases, pcap_root = _manifest(tmp_path, candidate)
    manifest_sha = hashlib.sha256(manifest.read_bytes()).hexdigest()
    monkeypatch.setattr(candidate_replay, "APPROVED_CASE_MANIFEST_SHA256", manifest_sha)
    monkeypatch.setattr(candidate_record, "APPROVED_CASE_MANIFEST_SHA256", manifest_sha)
    approved_cases = {case["id"]: (case["scenario"], case["pcap_sha256"]) for case in cases}
    monkeypatch.setattr(candidate_replay, "APPROVED_INDEPENDENT_CASES", approved_cases)
    monkeypatch.setattr(candidate_record, "APPROVED_INDEPENDENT_CASES", approved_cases)
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
    monkeypatch.setattr(key_pins, "PINNED_REPLAY_ED25519_SHA256", public_key_fingerprint(public))
    signed = attest_candidate_replay(
        candidate=candidate, artifact_dir=artifact, calibration_manifest=calibration,
        baseline_rules=baseline, case_manifest=manifest,
        expected_case_manifest_sha256=manifest_sha,
        isolated_yaml=config, pcap_root=pcap_root,
        manifest_prefix="data/private/fresh-holdouts-20261111", isolated_root=root,
        private_key_pem=private, private_key_password=PASSWORD,
        replay_public_pem=public, suricata_binary="suricata",
    )
    assert verify_record(signed, public, domain="isolated-replay-v1")
    assert signed["sid"] == 9103012
    assert {case["scenario"] for case in signed["cases"]} == {"attack", "normal"}
    assert len(list((root / "replay-evidence" / "signing-runs").iterdir())) == 1


def test_candidate_replay_signer_rejects_discovery_case_before_suricata(monkeypatch, tmp_path):
    candidate, artifact, calibration, baseline = _candidate(tmp_path)
    root = tmp_path / "isolated-candidate-9103012"
    root.mkdir()
    monkeypatch.setattr(candidate_replay, "APPROVED_VM1_ISOLATED_WORKSPACE", tmp_path)
    config = _config(root)
    manifest, _, pcap_root = _manifest(tmp_path, candidate)
    bad = json.loads(manifest.read_text(encoding="utf-8"))
    bad["cases"][0]["pcap_sha256"] = candidate["pcap_sha256"]
    manifest.write_text(json.dumps(bad), encoding="utf-8")
    manifest_sha = hashlib.sha256(manifest.read_bytes()).hexdigest()
    monkeypatch.setattr(candidate_replay, "APPROVED_CASE_MANIFEST_SHA256", manifest_sha)
    private, public = generate_encrypted_keypair(PASSWORD)
    monkeypatch.setattr(key_pins, "PINNED_REPLAY_ED25519_SHA256", public_key_fingerprint(public))
    called = []
    monkeypatch.setattr("netids.candidate_replay.subprocess.run", lambda *a, **k: called.append(a))
    with pytest.raises(CandidateReplayError, match="Discovery PCAP"):
        attest_candidate_replay(
            candidate=candidate, artifact_dir=artifact, calibration_manifest=calibration,
            baseline_rules=baseline, case_manifest=manifest,
            expected_case_manifest_sha256=manifest_sha,
            isolated_yaml=config, pcap_root=pcap_root,
            manifest_prefix="data/private/fresh-holdouts-20261111", isolated_root=root,
            private_key_pem=private, private_key_password=PASSWORD,
            replay_public_pem=public, suricata_binary="suricata",
        )
    assert called == []


def test_candidate_replay_rejects_self_consistent_unapproved_manifest_digest(tmp_path):
    candidate, artifact, calibration, baseline = _candidate(tmp_path)
    root = tmp_path / "isolated"
    root.mkdir()
    manifest, _, _ = _manifest(tmp_path, candidate)
    replacement_sha = hashlib.sha256(manifest.read_bytes()).hexdigest()
    with pytest.raises(CandidateReplayError, match="approved digest"):
        from netids.candidate_replay import load_independent_case_manifest
        load_independent_case_manifest(manifest, replacement_sha, candidate)


def test_failure_report_is_durable_and_never_claims_rollback_success(tmp_path):
    report_path = tmp_path / "failure.json"
    _write_failure_report(report_path, {
        "schema_version": "isolated_runtime_failure_v1",
        "failure_reason": "production before/after mismatch",
        "rollback_verified": False,
        "cleanup_status": "cleanup_unverified",
    })
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["schema_version"] == "isolated_runtime_failure_v1"
    assert report["rollback_verified"] is False
    with pytest.raises(OperationError, match="already exists"):
        _write_failure_report(report_path, report)


def test_manifest_path_resolution_rejects_absolute_traversal_outside_missing_and_hash_independent_paths(tmp_path):
    root = tmp_path / "fresh-holdouts-20261111"
    safe = root / "attack-holdout-02" / "traffic.pcap"
    safe.parent.mkdir(parents=True)
    safe.write_bytes(b"safe")
    prefix = "data/private/fresh-holdouts-20261111"
    assert resolve_manifest_pcap_path(
        f"{prefix}/attack-holdout-02/traffic.pcap", pcap_root=root, manifest_prefix=prefix,
    ) == safe.resolve()
    for bad in (
        "/etc/passwd",
        "C:/Windows/System32/config/SAM",
        f"{prefix}/../secret.pcap",
        "data/private/other/traffic.pcap",
        f"{prefix}/missing/traffic.pcap",
    ):
        with pytest.raises(CandidateReplayError):
            resolve_manifest_pcap_path(bad, pcap_root=root, manifest_prefix=prefix)
    for bad_prefix in ("", "/data/private", "C:/data/private", "data\\private", ".", "..", "data/./private", "data/../private"):
        with pytest.raises(CandidateReplayError, match="prefix"):
            resolve_manifest_pcap_path(
                f"{prefix}/attack-holdout-02/traffic.pcap", pcap_root=root,
                manifest_prefix=bad_prefix,
            )
    outside = tmp_path / "outside.pcap"
    outside.write_bytes(b"outside")
    escaped = root / "normal-holdout-01" / "traffic.pcap"
    escaped.parent.mkdir(parents=True)
    try:
        escaped.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable on this runner")
    with pytest.raises(CandidateReplayError, match="symlink"):
        resolve_manifest_pcap_path(
            f"{prefix}/normal-holdout-01/traffic.pcap", pcap_root=root, manifest_prefix=prefix,
        )


def test_candidate_isolated_root_rejects_root_and_parent_symlinks(monkeypatch, tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setattr(candidate_replay, "APPROVED_VM1_ISOLATED_WORKSPACE", workspace, raising=False)
    valid = workspace / "isolated-candidate-9103012"
    valid.mkdir()
    assert _validate_isolated_root(valid) == valid.resolve()
    root_link = workspace / "isolated-candidate-link"
    parent = workspace / "parent"
    parent.mkdir()
    try:
        root_link.symlink_to(valid, target_is_directory=True)
        parent_link = workspace / "parent-link"
        parent_link.symlink_to(parent, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable on this runner")
    with pytest.raises(CandidateReplayError, match="symlink"):
        _validate_isolated_root(root_link)
    with pytest.raises(CandidateReplayError, match="symlink"):
        _validate_isolated_root(parent_link / "isolated-candidate-9103012")


def test_candidate_isolated_root_rejects_lexical_traversal(monkeypatch, tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setattr(candidate_replay, "APPROVED_VM1_ISOLATED_WORKSPACE", workspace, raising=False)
    target = tmp_path / "isolated-candidate-9103012"
    target.mkdir()
    with pytest.raises(CandidateReplayError, match="traversal"):
        _validate_isolated_root(workspace / ".." / target.name)


def test_candidate_isolated_root_rejects_off_workspace_directory(monkeypatch, tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setattr(candidate_replay, "APPROVED_VM1_ISOLATED_WORKSPACE", workspace, raising=False)
    outside = tmp_path / "outside"
    outside.mkdir()
    candidate_named_outside = outside / "isolated-candidate-9103012"
    candidate_named_outside.mkdir()
    with pytest.raises(CandidateReplayError, match="approved workspace"):
        _validate_isolated_root(candidate_named_outside)


def test_candidate_replay_signer_rejects_unpinned_replay_key(monkeypatch, tmp_path):
    candidate, artifact, calibration, baseline = _candidate(tmp_path)
    root = tmp_path / "isolated-candidate-9103012"
    root.mkdir()
    monkeypatch.setattr(candidate_replay, "APPROVED_VM1_ISOLATED_WORKSPACE", tmp_path)
    config = _config(root)
    manifest, _, pcap_root = _manifest(tmp_path, candidate)
    with pytest.raises(CandidateReplayError, match="not independently pinned"):
        attest_candidate_replay(
            candidate=candidate, artifact_dir=artifact, calibration_manifest=calibration,
            baseline_rules=baseline, case_manifest=manifest,
            expected_case_manifest_sha256=APPROVED_CASE_MANIFEST_SHA256,
            isolated_yaml=config, pcap_root=pcap_root,
            manifest_prefix="data/private/fresh-holdouts-20261111", isolated_root=root,
            private_key_pem=b"", private_key_password=PASSWORD,
            replay_public_pem=b"not-a-key", suricata_binary="suricata",
        )


def test_candidate_replay_false_positive_gate_cannot_issue_attestation(monkeypatch, tmp_path):
    candidate, artifact, calibration, baseline = _candidate(tmp_path)
    root = tmp_path / "isolated-candidate-9103012"
    root.mkdir()
    monkeypatch.setattr(candidate_replay, "APPROVED_VM1_ISOLATED_WORKSPACE", tmp_path)
    config = _config(root)
    manifest, cases, pcap_root = _manifest(tmp_path, candidate)
    manifest_sha = hashlib.sha256(manifest.read_bytes()).hexdigest()
    monkeypatch.setattr(candidate_replay, "APPROVED_CASE_MANIFEST_SHA256", manifest_sha)
    monkeypatch.setattr(candidate_record, "APPROVED_CASE_MANIFEST_SHA256", manifest_sha)
    approved_cases = {case["id"]: (case["scenario"], case["pcap_sha256"]) for case in cases}
    monkeypatch.setattr(candidate_replay, "APPROVED_INDEPENDENT_CASES", approved_cases)
    monkeypatch.setattr(candidate_record, "APPROVED_INDEPENDENT_CASES", approved_cases)
    private, public = generate_encrypted_keypair(PASSWORD)
    monkeypatch.setattr(key_pins, "PINNED_REPLAY_ED25519_SHA256", public_key_fingerprint(public))

    def fake_run(argv, **kwargs):
        if "-r" in argv:
            logdir = Path(argv[argv.index("-l") + 1])
            logdir.mkdir(parents=True, exist_ok=True)
            (logdir / "eve.json").write_text(
                json.dumps({"event_type": "alert", "alert": {"signature_id": 9103012}}) + "\n",
                encoding="utf-8",
            )
        return SimpleNamespace(returncode=0, stdout="This is Suricata 8.0.3", stderr="")

    monkeypatch.setattr("netids.candidate_replay.subprocess.run", fake_run)
    with pytest.raises(CandidateReplayError, match="safety gate"):
        attest_candidate_replay(
            candidate=candidate, artifact_dir=artifact, calibration_manifest=calibration,
            baseline_rules=baseline, case_manifest=manifest,
            expected_case_manifest_sha256=manifest_sha,
            isolated_yaml=config, pcap_root=pcap_root,
            manifest_prefix="data/private/fresh-holdouts-20261111", isolated_root=root,
            private_key_pem=private, private_key_password=PASSWORD,
            replay_public_pem=public, suricata_binary="suricata",
        )
    assert not list((root / "replay-evidence" / "signing-runs").glob("*/attestation.json"))


def test_candidate_owner_authorization_binds_runtime_and_replay(tmp_path):
    candidate, artifact, calibration, baseline = _candidate(tmp_path)
    replay_private, replay_public = generate_encrypted_keypair(PASSWORD)
    owner_private, owner_public = generate_encrypted_keypair(PASSWORD)
    replay = {
        "schema_version": "isolated_replay_attestation_v1",
        **{key: candidate[key] for key in ("candidate_id", "run_id", "sid", "rule_sha256", "pcap_sha256", "model_sha256", "calibration_sha256", "decision_manifest_sha256", "source_rule_file_sha256", "source_metadata_sha256", "review_sha256", "baseline_rules_sha256")},
        "suricata_version": "8.0.3", "syntax_authenticated": True,
        "attack_replay_passed": True, "normal_replay_passed": True,
        "normal_false_positive_count": 0, "threshold": 3,
        "case_manifest_schema": "candidate_independent_replay_manifest_v1",
        "case_manifest_sha256": APPROVED_CASE_MANIFEST_SHA256,
        "minimum_attack_cases": 2, "minimum_normal_cases": 3,
        "experiment_id": "candidate-replay", "created_at": "2026-11-12T14:00:00+00:00",
        "cases": [
            {"run_id": "worker-attack-holdout-02-20261111", "scenario": "attack", "pcap_sha256": APPROVED_INDEPENDENT_CASES["worker-attack-holdout-02-20261111"][1], "eve_sha256": "2" * 64, "events": 1, "candidate_sid_alerts": 1},
            {"run_id": "worker-attack-holdout-03-20261111", "scenario": "attack", "pcap_sha256": APPROVED_INDEPENDENT_CASES["worker-attack-holdout-03-20261111"][1], "eve_sha256": "4" * 64, "events": 1, "candidate_sid_alerts": 1},
            {"run_id": "worker-normal-holdout-01-20261111", "scenario": "normal", "pcap_sha256": APPROVED_INDEPENDENT_CASES["worker-normal-holdout-01-20261111"][1], "eve_sha256": "6" * 64, "events": 1, "candidate_sid_alerts": 0},
            {"run_id": "worker-normal-holdout-02-20261111", "scenario": "normal", "pcap_sha256": APPROVED_INDEPENDENT_CASES["worker-normal-holdout-02-20261111"][1], "eve_sha256": "8" * 64, "events": 1, "candidate_sid_alerts": 0},
            {"run_id": "worker-normal-holdout-03-20261111", "scenario": "normal", "pcap_sha256": APPROVED_INDEPENDENT_CASES["worker-normal-holdout-03-20261111"][1], "eve_sha256": "a" * 64, "events": 1, "candidate_sid_alerts": 0},
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
