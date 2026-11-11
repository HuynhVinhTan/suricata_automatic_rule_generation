import pytest

from netids.hybrid_review import calibrate_hybrid_thresholds, evaluate_hybrid


def _normal(unique_ports=12, rst_count=0, syns=48, handshakes=48, payloads=48):
    return {
        "capture_integrity": {"capture_complete": True},
        "unique_destination_ports": unique_ports,
        "max_rst_count_per_window": rst_count,
        "initial_syn_packets": syns,
        "handshake_success_count": handshakes,
        "bidirectional_payload_count": payloads,
    }


def test_calibration_uses_only_normal_reference_evidence():
    thresholds = calibrate_hybrid_thresholds([
        _normal(unique_ports=2),
        _normal(unique_ports=12),
    ])

    assert thresholds == {
        "min_unique_destination_ports": 13,
        "min_rst_count_per_window": 1,
        "max_handshake_failure_count": 0,
    }


def test_attack_like_hybrid_evidence_passes_with_transparent_conditions():
    thresholds = calibrate_hybrid_thresholds([_normal()])
    result = evaluate_hybrid(
        ml_consensus=True,
        rst_evidence={
            "capture_integrity": {"capture_complete": True},
            "max_rst_count_per_window": 24,
        },
        port_evidence={"max_window_distinct_ports": 24},
        handshake_evidence={
            "initial_syn_packets": 24,
            "flows_with_confirmed_handshake": 0,
            "flows_with_bidirectional_payload": 0,
        },
        thresholds=thresholds,
    )

    assert result["classification"] == "reconnaissance_consistent"
    assert all(result["conditions"].values())
    assert result["requires_manual_review"] is True


def test_normal_with_some_failed_connections_does_not_pass():
    thresholds = calibrate_hybrid_thresholds([_normal()])
    result = evaluate_hybrid(
        ml_consensus=True,
        rst_evidence={
            "capture_integrity": {"capture_complete": True},
            "max_rst_count_per_window": 2,
        },
        port_evidence={"max_window_distinct_ports": 3},
        handshake_evidence={
            "initial_syn_packets": 24,
            "flows_with_confirmed_handshake": 22,
            "flows_with_bidirectional_payload": 22,
        },
        thresholds=thresholds,
    )

    assert result["classification"] == "anomalous_not_reconnaissance"
    assert result["conditions"]["ml_consensus"] is True
    assert result["conditions"]["rst_threshold"] is True
    assert result["conditions"]["port_diversity"] is False
    assert result["conditions"]["no_successful_handshake"] is False


def test_mixed_successful_and_failed_connections_stay_non_reconnaissance():
    thresholds = calibrate_hybrid_thresholds([_normal(unique_ports=12)])
    result = evaluate_hybrid(
        ml_consensus=True,
        rst_evidence={
            "capture_integrity": {"capture_complete": True},
            "max_rst_count_per_window": 2,
        },
        port_evidence={"max_window_distinct_ports": 13},
        handshake_evidence={
            "initial_syn_packets": 13,
            "flows_with_confirmed_handshake": 12,
            "flows_with_bidirectional_payload": 12,
        },
        thresholds=thresholds,
    )
    assert result["classification"] == "anomalous_not_reconnaissance"
    assert result["conditions"]["handshake_failure_exceeds_normal"] is True
    assert result["conditions"]["no_successful_handshake"] is False


def test_high_port_diversity_benign_service_checks_are_not_reconnaissance():
    thresholds = calibrate_hybrid_thresholds([_normal(unique_ports=12)])
    result = evaluate_hybrid(
        ml_consensus=True,
        rst_evidence={
            "capture_integrity": {"capture_complete": True},
            "max_rst_count_per_window": 0,
        },
        port_evidence={"max_window_distinct_ports": 13},
        handshake_evidence={
            "initial_syn_packets": 13,
            "flows_with_confirmed_handshake": 13,
            "flows_with_bidirectional_payload": 13,
        },
        thresholds=thresholds,
    )
    assert result["classification"] == "anomalous_not_reconnaissance"
    assert result["conditions"]["port_diversity"] is True
    assert result["conditions"]["no_successful_handshake"] is False


def test_incomplete_capture_is_ambiguous_and_never_passes():
    thresholds = calibrate_hybrid_thresholds([_normal()])
    result = evaluate_hybrid(
        ml_consensus=True,
        rst_evidence={
            "capture_integrity": {"capture_complete": None},
            "max_rst_count_per_window": 24,
        },
        port_evidence={"max_window_distinct_ports": 24},
        handshake_evidence={
            "initial_syn_packets": 24,
            "flows_with_confirmed_handshake": 0,
            "flows_with_bidirectional_payload": 0,
        },
        thresholds=thresholds,
    )

    assert result["classification"] == "ambiguous_incomplete_capture"
    assert result["requires_manual_review"] is True
    assert result["conditions"]["capture_complete"] is False


def test_calibration_rejects_incomplete_normal_reference():
    with pytest.raises(ValueError, match="complete"):
        calibrate_hybrid_thresholds([_normal(), {
            **_normal(),
            "capture_integrity": {"capture_complete": False},
        }])
