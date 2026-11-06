"""Regression tests for offline Port-Diversity review safety."""

import json

import pytest

from netids import pipeline
from netids.port_diversity import SynEvent
from netids.rulegen import build_syn_burst_review_rule


SRC = "192.168.10.20"
DST = "192.168.10.10"


@pytest.mark.parametrize(
    "ports, expected_peak, expected_trigger, consensus, benign_like",
    [
        (list(range(1000, 1008)), 8, True, 5, False),
        ([80, 443, 80, 443], 2, False, 3, True),
        ([80] * 61, 1, False, 6, True),
        (list(range(18080, 18088)), 8, True, 2, True),
        (list(range(20000, 20008)), 8, True, 0, False),
    ],
)
def test_pipeline_keeps_review_gate_closed(
    tmp_path,
    monkeypatch,
    ports,
    expected_peak,
    expected_trigger,
    consensus,
    benign_like,
):
    private = tmp_path / "private"
    private.mkdir()

    pcap = tmp_path / "fixture.pcap"
    pcap.write_bytes(b"mocked-pcap-for-review-contract")

    model_dir = (
        private / "lab-models" / "lab_syn_anomaly_v0_1"
    )
    model_dir.mkdir(parents=True)

    sessions = private / "lab-sessions" / "normal-batch-v01"
    sessions.mkdir(parents=True)

    reference_hashes = {}

    for partition in ("normal-train", "normal-cal"):
        reference = (
            sessions / f"syn_windows_10s_{partition}.csv"
        )
        reference.write_text(
            "label,window_seconds,syn_count\n"
            "NORMAL,10,1\n"
            "NORMAL,10,2\n",
            encoding="utf-8",
        )
        reference_hashes[partition] = pipeline.sha256(
            reference
        )

    model_report = model_dir / "report.json"
    model_report.write_text(
        json.dumps({
            "feature_csv_sha256": reference_hashes
        }),
        encoding="utf-8",
    )

    prior_dir = (
        private / "lab-rule-candidates" / "syn_scan_v0_1"
    )
    prior_dir.mkdir(parents=True)

    old_rule = build_syn_burst_review_rule(
        destination_ip=DST,
        normal_max_syn=2,
    )

    (prior_dir / "candidate.rules").write_text(
        old_rule + "\n",
        encoding="utf-8",
    )

    (prior_dir / "proposal.json").write_text(
        json.dumps({
            "status": "needs_review",
            "deployed": False,
            "model_report_sha256": pipeline.sha256(
                model_report
            ),
        }),
        encoding="utf-8",
    )

    def fake_extract(command, check):
        assert check is True
        assert "--out" in command

        feature_path = command[command.index("--out") + 1]

        from pathlib import Path

        path = Path(feature_path)
        path.write_text(
            "label,window_index,window_seconds,"
            "syn_count,unique_dst_ports\n"
            "UNLABELED,0,10,4,4\n",
            encoding="utf-8",
        )

    def fake_inference(
        private_root,
        feature_path,
        feature_sha,
        predictions_path,
    ):
        assert private_root == private
        assert feature_sha == pipeline.sha256(feature_path)

        predictions_path.write_text(
            json.dumps({
                "both_flagged": consensus,
                "model_sha256": "f" * 64,
                "input_sha256": feature_sha,
                "training_performed": False,
                "suricata_rule_generated": False,
                "rule_deployed": False,
            }),
            encoding="utf-8",
        )

    events = [
        SynEvent(
            timestamp=float(index * 2),
            src_ip=SRC,
            dst_ip=DST,
            dst_port=port,
        )
        for index, port in enumerate(ports)
    ]

    monkeypatch.setattr(
        pipeline.subprocess, "run", fake_extract
    )
    monkeypatch.setattr(
        pipeline, "run_inference", fake_inference
    )
    monkeypatch.setattr(
        pipeline, "read_pcap_syn", lambda path: events
    )

    def fake_handshake(
        path, *, source_ip, destination_ip
    ):
        assert path == pcap
        assert source_ip == SRC
        assert destination_ip == DST

        flow_count = len(ports)
        completed = flow_count if benign_like else 0

        return {
            "method": "offline_tcp_three_way_handshake_evidence",
            "evidence_type": "protocol_heuristic_not_ml",
            "initial_syn_packets": len(ports),
            "syn_flows": flow_count,
            "flows_with_confirmed_handshake": completed,
            "flows_with_bidirectional_payload": completed,
            "flows_with_server_payload": completed,
        }

    monkeypatch.setattr(
        pipeline, "summarize_tcp_handshake", fake_handshake
    )

    output = private / "acceptance"

    pipeline.run(
        pcap=pcap,
        expected_sha=pipeline.sha256(pcap),
        src=SRC,
        dst=DST,
        private_root=private,
        output_dir=output,
    )

    review = json.loads(
        (output / "review.json").read_text(
            encoding="utf-8"
        )
    )

    evidence = review["port_diversity_evidence"]

    assert review["model_consensus_flagged_windows"] == consensus
    assert review["schema_version"] == "lab_rule_review_v0_2"

    assert evidence["method"] == (
        "offline_pcap_sliding_unique_dst_ports"
    )
    assert evidence["evidence_type"] == (
        "heuristic_not_ml_model"
    )
    assert evidence["max_window_distinct_ports"] == expected_peak
    assert evidence["triggered"] is expected_trigger
    assert evidence["window_seconds"] == 60
    assert evidence["min_distinct_ports"] == 8

    assert evidence["independent_validation_passed"] is False
    assert evidence["automatic_rule_approval"] is False

    gate = review["candidate_gate"]

    assert gate["method"] == "ai_port_diversity_tcp_benign_veto_v1"
    assert gate["ai_consensus_present"] is (consensus > 0)
    assert gate["port_diversity_triggered"] is expected_trigger
    tcp = review["tcp_handshake_evidence"]

    assert tcp["method"] == (
        "offline_tcp_three_way_handshake_evidence"
    )
    assert tcp["initial_syn_packets"] == len(ports)
    assert tcp["benign_like_veto"] is benign_like
    assert tcp["proves_benign"] is False
    assert tcp["independent_validation_passed"] is False

    assert gate["tcp_completed_payload_veto"] is benign_like

    expected_gate = (
        consensus > 0 and expected_trigger and not benign_like
    )
    assert gate["passed"] is expected_gate
    assert gate["rule_approval_authorized"] is False

    triage = review["triage"]

    correlated = consensus > 0 and expected_trigger
    ambiguous = correlated and benign_like

    expected_reason = (
        "conflicting_tcp_completion_evidence"
        if ambiguous
        else "correlated_detection_requires_rule_review"
        if correlated
        else "no_correlated_detection_evidence"
    )

    assert triage["schema_version"] == "lab_triage_v0_1"
    assert triage["requires_manual_review"] is correlated
    assert triage["reason"] == expected_reason
    assert triage["tcp_completion_proves_benign"] is False
    assert triage["auto_approve"] is False
    assert triage["auto_deploy"] is False


    if expected_gate:
        assert review["status"] == "rejected_known_false_positive"
        assert review["matches_previous_failed_candidate"] is True
        assert review["rule_generated_in_this_run"] is True
    else:
        assert review["status"] == "no_candidate"
        assert review["matches_previous_failed_candidate"] is False
        assert review["rule_generated_in_this_run"] is False

    assert review["existing_candidate_sid"] == (
        9102001 if consensus > 0 else None
    )

    assert review["approved"] is False
    assert review["deployable"] is False
    assert review["deployed"] is False

    candidate_path = output / "candidate.rules"
    assert candidate_path.exists() is expected_gate

    if expected_gate:
        assert "sid:9102001;" in candidate_path.read_text(
            encoding="utf-8"
        )
