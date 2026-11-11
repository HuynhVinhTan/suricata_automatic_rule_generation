import pytest

from netids.correlation import build_correlation_envelope, stable_document_id


def test_correlation_envelope_binds_run_and_pcap_provenance():
    envelope = build_correlation_envelope(
        run_id="worker-attack-holdout-01-20261111",
        scenario="attack",
        pcap_sha256="a" * 64,
        manifest_sha256="b" * 64,
        eve_output_sha256="c" * 64,
        model_sha256="d" * 64,
        calibration_sha256="e" * 64,
        ai_summary_document_id=stable_document_id(
            "worker-attack-holdout-01-20261111", "a" * 64
        ),
        ai_summary_sha256="1" * 64,
        suricata_version="8.0.3",
        replay_rule_sha256="f" * 64,
        matched_eve_events=3,
        matched_flows=1,
        hybrid_classification="reconnaissance_consistent",
        review_status="needs_review",
        sid=9103003,
        correlation_level="event_verified",
    )

    assert envelope["pcap_sha256"] == "a" * 64
    assert envelope["matching_eve_events"] == 3
    assert envelope["approved"] is False
    assert envelope["deployed"] is False


def test_correlation_rejects_unknown_classification_or_negative_counts():
    with pytest.raises(ValueError):
        build_correlation_envelope(
            run_id="run-001",
            scenario="normal",
            pcap_sha256="a" * 64,
            manifest_sha256="b" * 64,
            eve_output_sha256="c" * 64,
            model_sha256="d" * 64,
            calibration_sha256="e" * 64,
            ai_summary_document_id="f" * 64,
            ai_summary_sha256="1" * 64,
            suricata_version="8.0.3",
            replay_rule_sha256="0" * 64,
            matched_eve_events=-1,
            matched_flows=0,
            hybrid_classification="made_up",
            review_status="no_candidate",
            sid=None,
            correlation_level="session_verified",
        )
