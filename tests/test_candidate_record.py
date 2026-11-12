import hashlib
import json

import pytest

from netids.candidate_record import (
    APPROVED_CASE_MANIFEST_SHA256,
    APPROVED_INDEPENDENT_CASES,
    CandidateRecordError,
    build_candidate_record,
    verify_candidate_record,
    verify_signed_replay_evidence,
)
from netids.lifecycle_ed25519 import generate_encrypted_keypair, sign_record
from netids.rule_lifecycle import RuleLifecycle


def _fixture(tmp_path):
    artifact = tmp_path / "lineage"
    artifact.mkdir()
    rule = 'alert tcp any any -> 192.168.10.10 any (detection_filter:track by_src,count 3,seconds 10; sid:9103012; rev:1;)\n'
    (artifact / "ml-generated.rules").write_text(rule, encoding="utf-8", newline="\n")
    model = "b" * 64
    pcap = "a" * 64
    (artifact / "ml-generated.metadata.json").write_text(json.dumps({
        "schema_version": "ml_rule_metadata_v1",
        "run_id": "lineage-test-01",
        "pcap_sha256": pcap,
        "model_sha256": model,
        "rule_sha256": hashlib.sha256(rule[:-1].encode()).hexdigest(),
        "status": "needs_review",
        "approved": False, "deployable": False, "deployed": False,
    }), encoding="utf-8")
    (artifact / "review.json").write_text(json.dumps({
        "schema_version": "lab_rule_review_v0_2",
        "source_pcap_sha256": pcap,
        "model_sha256": model,
        "generated_rule_sid": 9103012,
        "status": "needs_review",
        "rule_generated_in_this_run": True,
        "approved": False, "deployable": False, "deployed": False,
    }), encoding="utf-8")
    calibration = tmp_path / "calibration.json"
    calibration.write_text(json.dumps({
        "threshold_provenance": {"calibration_decision_sha256": "d" * 64}
    }), encoding="utf-8")
    baseline = tmp_path / "baseline.rules"
    baseline.write_text("alert tcp any any -> any any (sid:1; rev:1;)\n", encoding="utf-8")
    return artifact, calibration, baseline


def test_candidate_record_binds_new_lineage_and_is_review_only(tmp_path):
    artifact, calibration, baseline = _fixture(tmp_path)
    record = build_candidate_record(artifact, calibration, baseline)
    assert record["sid"] == 9103012
    assert record["decision_manifest_sha256"] == "d" * 64
    identity = {key: record[key] for key in (
        "run_id", "sid", "rule_sha256", "pcap_sha256", "model_sha256",
        "calibration_sha256", "decision_manifest_sha256",
    )}
    assert record["candidate_id"] == hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert verify_candidate_record(record)
    lifecycle = RuleLifecycle(tmp_path / "audit.jsonl", isolated_root=tmp_path / "isolated-lab")
    created = lifecycle.create_candidate(record)
    assert created["candidate_id"] == record["candidate_id"]


@pytest.mark.parametrize("field", ["candidate_id", "run_id", "rule_sha256", "pcap_sha256", "model_sha256", "calibration_sha256", "decision_manifest_sha256"])
def test_candidate_record_rejects_tampered_identity(tmp_path, field):
    artifact, calibration, baseline = _fixture(tmp_path)
    record = build_candidate_record(artifact, calibration, baseline)
    record[field] = "0" * 64 if field != "run_id" else "wrong-run"
    assert not verify_candidate_record(record)


def test_candidate_record_rejects_sid_collision(tmp_path):
    artifact, calibration, baseline = _fixture(tmp_path)
    baseline.write_text("alert tcp any any -> any any (sid:9103012; rev:1;)\n", encoding="utf-8")
    with pytest.raises(CandidateRecordError, match="collision"):
        build_candidate_record(artifact, calibration, baseline)


@pytest.mark.parametrize(
    "field",
    ["source_rule_file_sha256", "source_metadata_sha256", "review_sha256", "baseline_rules_sha256"],
)
def test_candidate_record_requires_source_artifact_hashes(tmp_path, field):
    artifact, calibration, baseline = _fixture(tmp_path)
    record = build_candidate_record(artifact, calibration, baseline)
    record.pop(field)
    assert not verify_candidate_record(record)


@pytest.mark.parametrize("value", ["A" * 64, "0" * 63, "not-a-sha"])
def test_candidate_record_rejects_malformed_source_hashes(tmp_path, value):
    artifact, calibration, baseline = _fixture(tmp_path)
    record = build_candidate_record(artifact, calibration, baseline)
    record["source_metadata_sha256"] = value
    assert not verify_candidate_record(record)


def test_candidate_record_rejects_tampered_rule_with_recomputed_identity(tmp_path):
    artifact, calibration, baseline = _fixture(tmp_path)
    record = build_candidate_record(artifact, calibration, baseline)
    record["rule"] = record["rule"].replace("sid:9103012", "sid:9103013")
    record["rule_sha256"] = hashlib.sha256(record["rule"].encode()).hexdigest()
    identity = {key: record[key] for key in (
        "run_id", "sid", "rule_sha256", "pcap_sha256", "model_sha256",
        "calibration_sha256", "decision_manifest_sha256",
    )}
    record["candidate_id"] = hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert not verify_candidate_record(record)


def test_candidate_record_rejects_sid_not_matching_embedded_rule(tmp_path):
    artifact, calibration, baseline = _fixture(tmp_path)
    record = build_candidate_record(artifact, calibration, baseline)
    record["sid"] = 9103013
    identity = {key: record[key] for key in (
        "run_id", "sid", "rule_sha256", "pcap_sha256", "model_sha256",
        "calibration_sha256", "decision_manifest_sha256",
    )}
    record["candidate_id"] = hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert not verify_candidate_record(record)


def test_signed_replay_evidence_must_bind_candidate_and_real_eve_hashes(tmp_path):
    artifact, calibration, baseline = _fixture(tmp_path)
    candidate = build_candidate_record(artifact, calibration, baseline)
    private, public = generate_encrypted_keypair(b"candidate-test-password")
    evidence = {
        "schema_version": "isolated_replay_attestation_v1",
        **{key: candidate[key] for key in (
            "candidate_id", "run_id", "sid", "rule_sha256", "pcap_sha256",
            "model_sha256", "calibration_sha256", "decision_manifest_sha256",
            "source_rule_file_sha256", "source_metadata_sha256", "review_sha256",
            "baseline_rules_sha256",
        )},
        "suricata_version": "8.0.3 RELEASE",
        "syntax_authenticated": True,
        "case_manifest_schema": "candidate_independent_replay_manifest_v1",
        "case_manifest_sha256": APPROVED_CASE_MANIFEST_SHA256,
        "minimum_attack_cases": 2, "minimum_normal_cases": 3,
        "cases": [
            {"run_id": "worker-attack-holdout-02-20261111", "scenario": "attack", "pcap_sha256": APPROVED_INDEPENDENT_CASES["worker-attack-holdout-02-20261111"][1], "eve_sha256": "2" * 64, "events": 2, "candidate_sid_alerts": 1},
            {"run_id": "worker-attack-holdout-03-20261111", "scenario": "attack", "pcap_sha256": APPROVED_INDEPENDENT_CASES["worker-attack-holdout-03-20261111"][1], "eve_sha256": "4" * 64, "events": 2, "candidate_sid_alerts": 1},
            {"run_id": "worker-normal-holdout-01-20261111", "scenario": "normal", "pcap_sha256": APPROVED_INDEPENDENT_CASES["worker-normal-holdout-01-20261111"][1], "eve_sha256": "6" * 64, "events": 2, "candidate_sid_alerts": 0},
            {"run_id": "worker-normal-holdout-02-20261111", "scenario": "normal", "pcap_sha256": APPROVED_INDEPENDENT_CASES["worker-normal-holdout-02-20261111"][1], "eve_sha256": "8" * 64, "events": 2, "candidate_sid_alerts": 0},
            {"run_id": "worker-normal-holdout-03-20261111", "scenario": "normal", "pcap_sha256": APPROVED_INDEPENDENT_CASES["worker-normal-holdout-03-20261111"][1], "eve_sha256": "a" * 64, "events": 2, "candidate_sid_alerts": 0},
        ],
    }
    signed = sign_record(evidence, private, b"candidate-test-password", domain="isolated-replay-v1")
    assert verify_signed_replay_evidence(candidate, signed, public)
    tampered = {key: value for key, value in signed.items() if not key.startswith("attestation_")}
    tampered["rule_sha256"] = "0" * 64
    assert not verify_signed_replay_evidence(candidate, tampered, public)


def test_signed_replay_evidence_binds_source_hashes_and_exact_case_inventory(tmp_path):
    artifact, calibration, baseline = _fixture(tmp_path)
    candidate = build_candidate_record(artifact, calibration, baseline)
    private, public = generate_encrypted_keypair(b"candidate-test-password")
    evidence = {
        "schema_version": "isolated_replay_attestation_v1",
        **{key: candidate[key] for key in (
            "candidate_id", "run_id", "sid", "rule_sha256", "pcap_sha256",
            "model_sha256", "calibration_sha256", "decision_manifest_sha256",
            "source_rule_file_sha256", "source_metadata_sha256", "review_sha256",
            "baseline_rules_sha256",
        )},
        "suricata_version": "8.0.3 RELEASE",
        "syntax_authenticated": True,
        "case_manifest_schema": "candidate_independent_replay_manifest_v1",
        "case_manifest_sha256": APPROVED_CASE_MANIFEST_SHA256,
        "minimum_attack_cases": 2, "minimum_normal_cases": 3,
        "cases": [
            {"run_id": "worker-attack-holdout-02-20261111", "scenario": "attack", "pcap_sha256": APPROVED_INDEPENDENT_CASES["worker-attack-holdout-02-20261111"][1], "eve_sha256": "2" * 64, "events": 2, "candidate_sid_alerts": 1},
            {"run_id": "worker-attack-holdout-03-20261111", "scenario": "attack", "pcap_sha256": APPROVED_INDEPENDENT_CASES["worker-attack-holdout-03-20261111"][1], "eve_sha256": "4" * 64, "events": 2, "candidate_sid_alerts": 1},
            {"run_id": "worker-normal-holdout-01-20261111", "scenario": "normal", "pcap_sha256": APPROVED_INDEPENDENT_CASES["worker-normal-holdout-01-20261111"][1], "eve_sha256": "6" * 64, "events": 2, "candidate_sid_alerts": 0},
            {"run_id": "worker-normal-holdout-02-20261111", "scenario": "normal", "pcap_sha256": APPROVED_INDEPENDENT_CASES["worker-normal-holdout-02-20261111"][1], "eve_sha256": "8" * 64, "events": 2, "candidate_sid_alerts": 0},
            {"run_id": "worker-normal-holdout-03-20261111", "scenario": "normal", "pcap_sha256": APPROVED_INDEPENDENT_CASES["worker-normal-holdout-03-20261111"][1], "eve_sha256": "a" * 64, "events": 2, "candidate_sid_alerts": 0},
        ],
    }
    signed = sign_record(evidence, private, b"candidate-test-password", domain="isolated-replay-v1")
    assert verify_signed_replay_evidence(candidate, signed, public)
    for field in (
        "candidate_id", "run_id", "sid", "rule_sha256", "source_rule_file_sha256",
        "source_metadata_sha256", "review_sha256", "pcap_sha256", "model_sha256",
        "calibration_sha256", "decision_manifest_sha256", "baseline_rules_sha256",
    ):
        tampered = {key: value for key, value in signed.items() if not key.startswith("attestation_")}
        tampered[field] = 0 if field == "sid" else ("wrong-run" if field == "run_id" else "f" * 64)
        tampered = sign_record(tampered, private, b"candidate-test-password", domain="isolated-replay-v1")
        assert not verify_signed_replay_evidence(candidate, tampered, public)
    changed_case = [dict(case) for case in signed["cases"]]
    changed_case[0]["run_id"] = "worker-attack-holdout-01-20261111"
    tampered = {key: value for key, value in signed.items() if not key.startswith("attestation_")}
    tampered["cases"] = changed_case
    tampered = sign_record(tampered, private, b"candidate-test-password", domain="isolated-replay-v1")
    assert not verify_signed_replay_evidence(candidate, tampered, public)


def test_signed_replay_rejects_discovery_pcap_as_independent_case(tmp_path):
    artifact, calibration, baseline = _fixture(tmp_path)
    candidate = build_candidate_record(artifact, calibration, baseline)
    private, public = generate_encrypted_keypair(b"candidate-test-password")
    evidence = {
        "schema_version": "isolated_replay_attestation_v1",
        **{key: candidate[key] for key in (
            "candidate_id", "run_id", "sid", "rule_sha256", "pcap_sha256",
            "model_sha256", "calibration_sha256", "decision_manifest_sha256",
        )},
        "suricata_version": "8.0.3 RELEASE",
        "syntax_authenticated": True,
        "case_manifest_schema": "candidate_independent_replay_manifest_v1",
        "case_manifest_sha256": APPROVED_CASE_MANIFEST_SHA256,
        "minimum_attack_cases": 2, "minimum_normal_cases": 3,
        "cases": [
            {"scenario": "attack", "pcap_sha256": candidate["pcap_sha256"], "eve_sha256": "2" * 64, "events": 2, "candidate_sid_alerts": 1},
            {"scenario": "attack", "pcap_sha256": "3" * 64, "eve_sha256": "4" * 64, "events": 2, "candidate_sid_alerts": 1},
            {"scenario": "normal", "pcap_sha256": "5" * 64, "eve_sha256": "6" * 64, "events": 2, "candidate_sid_alerts": 0},
            {"scenario": "normal", "pcap_sha256": "7" * 64, "eve_sha256": "8" * 64, "events": 2, "candidate_sid_alerts": 0},
            {"scenario": "normal", "pcap_sha256": "9" * 64, "eve_sha256": "a" * 64, "events": 2, "candidate_sid_alerts": 0},
        ],
    }
    signed = sign_record(evidence, private, b"candidate-test-password", domain="isolated-replay-v1")
    assert not verify_signed_replay_evidence(candidate, signed, public)
