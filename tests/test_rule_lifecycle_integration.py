"""Offline registration tests; no network, Suricata service, or VM access."""

import hashlib
import json

import pytest

from netids.lifecycle_integration import register_generated_candidate
from netids.rule_lifecycle import LifecycleError


def _hash(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sources(tmp_path, *, sid=9103999):
    artifact = tmp_path / "existing-worker-output"
    artifact.mkdir(parents=True)
    rule = (
        f'alert tcp 192.0.2.10 any -> 192.0.2.20 any '
        f'(msg:"synthetic review artifact"; flags:R+; sid:{sid}; rev:1;)'
    )
    (artifact / "ml-generated-rst.rules").write_text(rule + "\n", encoding="utf-8")
    metadata = {
        "schema_version": "ml_rst_rule_metadata_v1",
        "candidate_family": "rst_response_v1",
        "run_id": "synthetic-run",
        "status": "needs_review",
        "approved": False,
        "deployable": False,
        "deployed": False,
        "pcap_sha256": "a" * 64,
        "model_sha256": "b" * 64,
        "rule_sha256": _hash(rule.encode("utf-8")),
        "normal_calibration_provenance": {
            "status": "accepted",
            "final_holdout_used": False,
            "frozen_before_holdouts": True,
        },
        "normal_validation_evidence": {
            "pcap_sha256": "c" * 64,
            "capture_integrity": {"capture_complete": True},
        },
        "development_evidence": {
            "scope": "G4_DEVELOPMENT_ONLY",
            "native_replay_tested": False,
            "independent_final_acceptance": False,
            "generator_sha256": "d" * 64,
            "calibration_sha256": "e" * 64,
            "calibration_references": [{
                "ground_truth_label": "NORMAL",
                "capture_metadata": {
                    "packet_records_complete": True,
                    "snaplen_truncated": False,
                    "capture_drops": False,
                },
            }],
        },
        "hybrid_evidence": {
            "classification": "reconnaissance_consistent",
            "python_only": True,
            "suricata_signature_equivalent": False,
        },
    }
    metadata_path = artifact / "ml-generated-rst.metadata.json"
    metadata_path.write_text(json.dumps(metadata) + "\n", encoding="utf-8")
    calibration = tmp_path / "verified-calibration.json"
    calibration.write_text('{"version":"synthetic"}\n', encoding="utf-8")
    baseline = tmp_path / "baseline.rules"
    baseline.write_text(
        'alert tcp any any -> 192.0.2.10 any (msg:"baseline"; sid:900001; rev:1;)\n',
        encoding="utf-8",
    )
    return {
        "artifact_dir": artifact,
        "run_id": "synthetic-run",
        "calibration_manifest": calibration,
        "expected_calibration_sha256": _hash(calibration.read_bytes()),
        "baseline_rules": baseline,
        "expected_baseline_sha256": _hash(baseline.read_bytes()),
        "audit_path": tmp_path / "audit.jsonl",
        "isolated_root": tmp_path / "isolated-lab",
    }


def test_existing_generated_artifact_registers_only_proposed_candidate(tmp_path):
    args = _sources(tmp_path)
    result = register_generated_candidate(**args)
    assert result["status"] == "PROPOSED"
    assert result["sid"] == 9103999
    assert result["audit_records"] == 1
    assert result["approved"] is False
    assert result["deployable"] is False
    assert result["deployed"] is False
    assert not list((tmp_path / "isolated-lab").glob("*.rules"))
    assert (tmp_path / "existing-worker-output" / "ml-generated-rst.rules").is_file()


def test_registration_rejects_unpinned_calibration_and_baseline(tmp_path):
    args = _sources(tmp_path)
    args["calibration_manifest"].write_text('{"version":"changed"}\n', encoding="utf-8")
    with pytest.raises(LifecycleError, match="calibration manifest SHA256"):
        register_generated_candidate(**args)
    assert not args["audit_path"].exists()


def test_registration_rejects_sid_collision_and_unsafe_metadata(tmp_path):
    args = _sources(tmp_path, sid=900001)
    with pytest.raises(LifecycleError, match="conflicting SID"):
        register_generated_candidate(**args)


def test_acceptance_path_rejects_legacy_identity_without_candidate_record(tmp_path):
    args = _sources(tmp_path)
    with pytest.raises(LifecycleError, match="candidate_record_v1"):
        register_generated_candidate(**args, require_candidate_record=True)
    args = _sources(tmp_path / "separate", sid=9103998)
    metadata_path = args["artifact_dir"] / "ml-generated-rst.metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["approved"] = True
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    with pytest.raises(LifecycleError, match="provenance"):
        register_generated_candidate(**args)
