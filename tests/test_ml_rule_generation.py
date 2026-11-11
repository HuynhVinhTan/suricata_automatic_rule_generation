import json
import re

import pytest

from netids import rulegen
from backend import worker


def test_allocates_fresh_sid_away_from_rejected_and_existing_sids():
    assert hasattr(rulegen, "allocate_sid")
    assert rulegen.allocate_sid({9103000, 9103001, 9103002, 9102001, 9102002}) == 9103003


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

    assert result["status"] == "needs_review"
    assert result["sid"] == 9103003
    assert result["threshold"] == 3
    assert "sid:9102001;" not in result["rule"]
    assert "sid:9102002;" not in result["rule"]
    assert 'msg:"ML REVIEW - SYN packet burst"; flow:stateless;' in result["rule"]
    assert "detection_filter:track by_src,count 3,seconds 10;" in result["rule"]
    assert "unique" not in result["rule"].lower()
    assert result["metadata"]["run_id"] == "recon-001"
    assert result["metadata"]["pcap_sha256"] == "a" * 64
    assert result["metadata"]["model_sha256"] == "b" * 64
    assert result["metadata"]["rule_sha256"]
    assert re.fullmatch(r"[0-9a-f]{64}", result["metadata"]["rule_sha256"])

    rulegen.write_ml_rule_artifacts(tmp_path, result)
    rule_path = tmp_path / "ml-generated.rules"
    metadata_path = tmp_path / "ml-generated.metadata.json"
    assert rule_path.read_text(encoding="utf-8").strip() == result["rule"]
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


def test_worker_validates_generated_artifact_provenance(tmp_path):
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
        "status": "needs_review",
        "generated_rule": result["rule"],
        "generated_rule_sid": result["sid"],
        "generated_rule_metadata": result["metadata"],
    }

    worker._validate_generated_rule_artifacts(
        tmp_path,
        review,
        run_id="recon-004",
        pcap_sha256="a" * 64,
        model_sha256="b" * 64,
    )

    metadata = json.loads(
        (tmp_path / "ml-generated.metadata.json").read_text(encoding="utf-8")
    )
    metadata["pcap_sha256"] = "c" * 64
    (tmp_path / "ml-generated.metadata.json").write_text(
        json.dumps(metadata), encoding="utf-8"
    )
    with pytest.raises(worker.WorkerProcessingError, match="provenance"):
        worker._validate_generated_rule_artifacts(
            tmp_path,
            review,
            run_id="recon-004",
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
        existing_sids=[9103000, 9103001, 9103002],
    )
    assert result["status"] == "needs_review"
    assert result["sid"] == 9103003
    assert 'flags:R+;' in result["rule"]
    assert "track by_dst" in result["rule"]
    assert result["metadata"]["rule_sha256"]
    assert result["metadata"]["approved"] is False

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
    )
    assert result["rejection_reason"] == "incomplete_capture_evidence"
