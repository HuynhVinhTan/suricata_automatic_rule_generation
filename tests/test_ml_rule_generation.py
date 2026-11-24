import json
import re

import pytest

from netids import rulegen
from backend import worker


_DEV_EVIDENCE = {
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
}
_HYBRID_EVIDENCE = {
    "classification": "reconnaissance_consistent",
    "python_only": True,
    "suricata_signature_equivalent": False,
}


def test_allocates_fresh_sid_away_from_rejected_and_existing_sids():
    assert hasattr(rulegen, "allocate_sid")
    assert rulegen.allocate_sid({9103000, 9103001, 9103002, 9102001, 9102002}) == 9103005


def test_historical_rejected_sid_9103012_is_never_allocated_or_accepted():
    assert 9103012 in rulegen.REJECTED_SIDS
    assert rulegen.allocate_sid(set(range(9103000, 9103013))) == 9103013
    with pytest.raises(ValueError, match="Rejected historical SID"):
        rulegen._build_ml_syn_rule(
            destination_ip="192.0.2.10",
            threshold=3,
            window_seconds=10,
            sid=9103012,
        )


def test_syn_packet_count_family_is_quarantined_after_native_false_positive():
    assert {9103000, 9103003, 9103004}.issubset(rulegen.REJECTED_SIDS)

    result = rulegen.generate_ml_rule(
        run_id="recon-syn-false-positive",
        pcap_sha256="a" * 64,
        model_sha256="b" * 64,
        destination_ip="192.0.2.10",
        normal_train_syn_counts=[1, 2],
        normal_cal_syn_counts=[2, 2],
        normal_test_syn_counts=[1, 2],
        attack_syn_counts=[11, 10, 9],
        existing_sids={9103000, 9103001, 9103002},
    )

    assert result["status"] == "rejected_validation_failure"
    assert result["rejection_reason"] == "quarantined_syn_packet_count_family"
    assert result["rule"] is None
    assert result["metadata"]["candidate_family"] == "syn_packet_count_v1"


def test_generates_rule_and_provenance_metadata_from_evidence(tmp_path):
    result = rulegen.generate_ml_rule(
        run_id="recon-001",
        pcap_sha256="a" * 64,
        model_sha256="b" * 64,
        destination_ip="192.0.2.10",
        normal_train_syn_counts=[1, 2],
        normal_cal_syn_counts=[2, 2],
        normal_test_syn_counts=[1, 2],
        attack_syn_counts=[4, 5],
        existing_sids={9103000, 9103001, 9103002},
    )

    assert result["status"] == "rejected_validation_failure"
    assert result["sid"] is None
    assert result["threshold"] == 3
    assert result["rejection_reason"] == "quarantined_syn_packet_count_family"
    assert result["rule"] is None
    assert result["metadata"]["run_id"] == "recon-001"
    assert result["metadata"]["pcap_sha256"] == "a" * 64
    assert result["metadata"]["model_sha256"] == "b" * 64
    assert result["metadata"]["candidate_family"] == "syn_packet_count_v1"
    assert result["metadata"]["rule_sha256"] is None

    rulegen.write_ml_rule_artifacts(tmp_path, result)
    metadata_path = tmp_path / "ml-generated.metadata.json"
    assert json.loads(metadata_path.read_text(encoding="utf-8"))["rule_sha256"] == result["metadata"]["rule_sha256"]


def test_rejects_candidate_that_fires_on_normal_validation():
    result = rulegen.generate_ml_rule(
        run_id="recon-002",
        pcap_sha256="a" * 64,
        model_sha256="b" * 64,
        destination_ip="192.0.2.10",
        normal_train_syn_counts=[1, 2],
        normal_cal_syn_counts=[2],
        normal_test_syn_counts=[3],
        attack_syn_counts=[4],
    )

    assert result["status"] == "rejected_validation_failure"
    assert result["rejection_reason"] == "normal_validation_false_positive"
    assert result["rule"] is None
    assert result["metadata"]["rule_sha256"] is None


def test_worker_rejects_quarantined_syn_artifact_family(tmp_path):
    result = rulegen.generate_ml_rule(
        run_id="recon-004",
        pcap_sha256="a" * 64,
        model_sha256="b" * 64,
        destination_ip="192.0.2.10",
        normal_train_syn_counts=[1],
        normal_cal_syn_counts=[1],
        normal_test_syn_counts=[1],
        attack_syn_counts=[3],
    )
    rulegen.write_ml_rule_artifacts(tmp_path, result)
    review = {
        "rule_generated_in_this_run": True,
        "status": "rejected_validation_failure",
        "generated_rule": result["rule"],
        "generated_rule_sid": result["sid"],
        "generated_rule_metadata": result["metadata"],
    }

    with pytest.raises(worker.WorkerProcessingError, match="permanently quarantined"):
        worker._validate_generated_rule_artifacts(
            tmp_path,
            review,
            run_id="recon-004",
            pcap_sha256="a" * 64,
            model_sha256="b" * 64,
        )


def test_worker_validates_rst_artifact_family_provenance(tmp_path):
    result = rulegen.generate_rst_rule(
        run_id="rst-worker-01",
        pcap_sha256="a" * 64,
        model_sha256="b" * 64,
        source_ip="192.168.10.10",
        destination_ip="192.168.10.20",
        normal_cal_rst_counts=[0, 1],
        normal_validation_rst_counts=[0],
        attack_rst_counts=[3],
        ml_consensus=True,
        port_diversity_triggered=True,
        rst_evidence={
            "rst_count": 3,
            "capture_integrity": {"capture_complete": True},
        },
        normal_calibration_provenance={
            "status": "accepted",
            "final_holdout_used": False,
            "frozen_before_holdouts": True,
        },
        normal_validation_evidence={
            "pcap_sha256": "c" * 64,
            "capture_integrity": {"capture_complete": True},
        },
        development_evidence=_DEV_EVIDENCE,
        hybrid_evidence=_HYBRID_EVIDENCE,
    )
    rulegen.write_rst_rule_artifacts(tmp_path, result)
    review = {
        "rule_generated_in_this_run": True,
        "status": "needs_review",
        "generated_rule": result["rule"],
        "generated_rule_sid": result["sid"],
        "generated_rule_family": "rst_response_v1",
        "generated_rule_metadata": result["metadata"],
    }

    worker._validate_generated_rule_artifacts(
        tmp_path,
        review,
        run_id="rst-worker-01",
        pcap_sha256="a" * 64,
        model_sha256="b" * 64,
    )


def test_replay_validation_rejects_normal_false_positive(tmp_path):
    result = rulegen.generate_ml_rule(
        run_id="recon-005",
        pcap_sha256="a" * 64,
        model_sha256="b" * 64,
        destination_ip="192.0.2.10",
        normal_train_syn_counts=[1],
        normal_cal_syn_counts=[1],
        normal_test_syn_counts=[1],
        attack_syn_counts=[3],
    )
    rulegen.write_ml_rule_artifacts(tmp_path, result)

    rejected = rulegen.apply_replay_validation(
        tmp_path,
        attack_alerts=4,
        normal_alerts=1,
    )

    assert rejected["status"] == "rejected_validation_failure"
    assert rejected["rejection_reason"] == "normal_replay_false_positive"
    assert rejected["normal_replay_alerts"] == 1
    assert rejected["attack_replay_alerts"] == 4
    assert rejected["deployable"] is False


def test_replay_validation_updates_rst_family_metadata(tmp_path):
    result = rulegen.generate_rst_rule(
        run_id="rst-replay-01",
        pcap_sha256="a" * 64,
        model_sha256="b" * 64,
        source_ip="192.168.10.10",
        destination_ip="192.168.10.20",
        normal_cal_rst_counts=[0, 1],
        normal_validation_rst_counts=[0],
        attack_rst_counts=[3],
        ml_consensus=True,
        port_diversity_triggered=True,
        rst_evidence={
            "rst_count": 3,
            "capture_integrity": {"capture_complete": True},
        },
        normal_calibration_provenance={
            "status": "accepted",
            "final_holdout_used": False,
            "frozen_before_holdouts": True,
        },
        normal_validation_evidence={
            "pcap_sha256": "c" * 64,
            "capture_integrity": {"capture_complete": True},
        },
        development_evidence=_DEV_EVIDENCE,
        hybrid_evidence=_HYBRID_EVIDENCE,
    )
    rulegen.write_rst_rule_artifacts(tmp_path, result)

    accepted = rulegen.apply_replay_validation(
        tmp_path,
        attack_alerts=3,
        normal_alerts=0,
    )

    assert accepted["schema_version"] == "ml_rst_rule_metadata_v1"
    assert accepted["normal_replay_passed"] is True
    assert json.loads(
        (tmp_path / "ml-generated-rst.metadata.json").read_text(encoding="utf-8")
    )["attack_replay_alerts"] == 3


@pytest.mark.parametrize(
    "field,value",
    [("run_id", "../escape"), ("pcap_sha256", "not-a-hash"), ("model_sha256", "x" * 63)],
)
def test_rejects_invalid_provenance(field, value):
    arguments = {
        "run_id": "recon-003",
        "pcap_sha256": "a" * 64,
        "model_sha256": "b" * 64,
        "destination_ip": "192.0.2.10",
        "normal_train_syn_counts": [1],
        "normal_cal_syn_counts": [1],
        "normal_test_syn_counts": [1],
        "attack_syn_counts": [3],
    }
    arguments[field] = value
    with pytest.raises(ValueError):
        rulegen.generate_ml_rule(**arguments)


def test_generates_rst_rule_only_with_all_independent_gates(tmp_path):
    result = rulegen.generate_rst_rule(
        run_id="rst-v01",
        pcap_sha256="a" * 64,
        model_sha256="b" * 64,
        source_ip="192.168.10.10",
        destination_ip="192.168.10.20",
        normal_cal_rst_counts=[0, 1],
        normal_validation_rst_counts=[0],
        attack_rst_counts=[3, 4],
        ml_consensus=True,
        port_diversity_triggered=True,
        rst_evidence={
            "rst_count": 4,
            "rst_ratio": 1.0,
            "capture_integrity": {"capture_complete": True},
        },
        normal_calibration_provenance={
            "status": "accepted",
            "final_holdout_used": False,
            "frozen_before_holdouts": True,
        },
        normal_validation_evidence={
            "pcap_sha256": "c" * 64,
            "capture_integrity": {"capture_complete": True},
        },
        development_evidence=_DEV_EVIDENCE,
        hybrid_evidence=_HYBRID_EVIDENCE,
        existing_sids=[9103000, 9103001, 9103002],
    )
    assert result["status"] == "needs_review"
    assert result["sid"] == 9103005
    assert 'flags:R+;' in result["rule"]
    assert "track by_dst" in result["rule"]
    assert result["metadata"]["rule_sha256"]
    assert result["metadata"]["approved"] is False
    assert result["metadata"]["candidate_family"] == "rst_response_v1"
    assert result["metadata"]["bounded_laboratory_signature"] is True
    assert result["metadata"]["hybrid_equivalent"] is False

    rulegen.write_rst_rule_artifacts(tmp_path, result)
    assert (tmp_path / "ml-generated-rst.rules").read_text(encoding="utf-8").strip() == result["rule"]
    rst_metadata = json.loads((tmp_path / "ml-generated-rst.metadata.json").read_text(encoding="utf-8"))
    assert rst_metadata["pcap_sha256"] == "a" * 64


def test_rst_rule_rejects_normal_validation_and_missing_ml():
    common = dict(
        run_id="rst-v02", pcap_sha256="a" * 64, model_sha256="b" * 64,
        source_ip="192.168.10.10", destination_ip="192.168.10.20",
        normal_cal_rst_counts=[0, 1], attack_rst_counts=[3],
        port_diversity_triggered=True,
        rst_evidence={"rst_count": 3, "capture_integrity": {"capture_complete": True}},
        normal_calibration_provenance={
            "status": "accepted",
            "final_holdout_used": False,
            "frozen_before_holdouts": True,
        },
        normal_validation_evidence={
            "pcap_sha256": "c" * 64,
            "capture_integrity": {"capture_complete": True},
        },
        development_evidence=_DEV_EVIDENCE,
        hybrid_evidence=_HYBRID_EVIDENCE,
    )
    normal = rulegen.generate_rst_rule(**common, normal_validation_rst_counts=[2], ml_consensus=True)
    assert normal["rejection_reason"] == "normal_validation_false_positive"
    no_ml = rulegen.generate_rst_rule(**common, normal_validation_rst_counts=[0], ml_consensus=False)
    assert no_ml["rejection_reason"] == "missing_ml_consensus"


def test_rst_rule_rejects_unknown_capture_completeness():
    result = rulegen.generate_rst_rule(
        run_id="rst-v03",
        pcap_sha256="a" * 64,
        model_sha256="b" * 64,
        source_ip="192.168.10.10",
        destination_ip="192.168.10.20",
        normal_cal_rst_counts=[0],
        normal_validation_rst_counts=[0],
        attack_rst_counts=[3],
        ml_consensus=True,
        port_diversity_triggered=True,
        rst_evidence={"rst_count": 3, "capture_integrity": {"capture_complete": None}},
        development_evidence=_DEV_EVIDENCE,
        hybrid_evidence=_HYBRID_EVIDENCE,
    )
    assert result["rejection_reason"] == "incomplete_capture_evidence"


def test_rst_rule_requires_verified_development_evidence():
    result = rulegen.generate_rst_rule(
        run_id="rst-no-development-evidence",
        pcap_sha256="a" * 64,
        model_sha256="b" * 64,
        source_ip="192.168.10.10",
        destination_ip="192.168.10.20",
        normal_cal_rst_counts=[0, 1],
        normal_validation_rst_counts=[0],
        attack_rst_counts=[3],
        ml_consensus=True,
        port_diversity_triggered=True,
        rst_evidence={"rst_count": 3, "capture_integrity": {"capture_complete": True}},
        normal_calibration_provenance={
            "status": "accepted",
            "final_holdout_used": False,
            "frozen_before_holdouts": True,
        },
        normal_validation_evidence={
            "pcap_sha256": "c" * 64,
            "capture_integrity": {"capture_complete": True},
        },
    )
    assert result["rejection_reason"] == "missing_verified_development_evidence"


def test_rst_rule_rejects_incomplete_development_capture():
    development = dict(_DEV_EVIDENCE)
    development["calibration_references"] = [{
        "ground_truth_label": "NORMAL",
        "capture_metadata": {
            "packet_records_complete": True,
            "snaplen_truncated": True,
            "capture_drops": False,
        },
    }]
    result = rulegen.generate_rst_rule(
        run_id="rst-incomplete-development-capture",
        pcap_sha256="a" * 64,
        model_sha256="b" * 64,
        source_ip="192.168.10.10",
        destination_ip="192.168.10.20",
        normal_cal_rst_counts=[0, 1],
        normal_validation_rst_counts=[0],
        attack_rst_counts=[3],
        ml_consensus=True,
        port_diversity_triggered=True,
        rst_evidence={"rst_count": 3, "capture_integrity": {"capture_complete": True}},
        normal_calibration_provenance={
            "status": "accepted",
            "final_holdout_used": False,
            "frozen_before_holdouts": True,
        },
        normal_validation_evidence={
            "pcap_sha256": "c" * 64,
            "capture_integrity": {"capture_complete": True},
        },
        development_evidence=development,
        hybrid_evidence=_HYBRID_EVIDENCE,
    )
    assert result["rejection_reason"] == "missing_verified_development_evidence"


def test_rst_signature_is_bounded_when_legitimate_repeated_rst_is_outside_normal_distribution():
    result = rulegen.generate_rst_rule(
        run_id="rst-bounded-lab-signature",
        pcap_sha256="a" * 64,
        model_sha256="b" * 64,
        source_ip="192.168.10.10",
        destination_ip="192.168.10.20",
        normal_cal_rst_counts=[2, 2, 0],
        normal_validation_rst_counts=[2],
        attack_rst_counts=[3],
        ml_consensus=True,
        port_diversity_triggered=True,
        rst_evidence={
            "rst_count": 3,
            "max_rst_count_per_window": 3,
            "capture_integrity": {"capture_complete": True},
        },
        normal_calibration_provenance={
            "status": "accepted",
            "final_holdout_used": False,
            "frozen_before_holdouts": True,
        },
        normal_validation_evidence={
            "pcap_sha256": "c" * 64,
            "capture_integrity": {"capture_complete": True},
        },
        development_evidence=_DEV_EVIDENCE,
        hybrid_evidence=_HYBRID_EVIDENCE,
    )
    assert result["status"] == "needs_review"
    assert result["metadata"]["hybrid_equivalent"] is False
