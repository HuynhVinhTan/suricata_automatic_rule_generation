import json

import pytest

from netids.hybrid_provenance import load_calibration_provenance
from netids.lab_runtime import sha256


def _manifest(path, *, label="NORMAL", metadata=None):
    return {
        "schema_version": "hybrid_normal_calibration_v1",
        "feature_definition": "TCP SYN destination-port sliding diversity",
        "window_seconds": 60,
        "references": [{
            "path": "reference.pcap",
            "sha256": sha256(path),
            "ground_truth_label": label,
            "ground_truth_source": "owner_capture_log",
            "source_ipv4": "192.168.10.20",
            "destination_ipv4": "192.168.10.10",
            "capture_metadata": metadata,
        }],
        "threshold_provenance": {
            "method": "max_complete_normal_reference_plus_one",
            "final_holdout_used": False,
        },
    }


def test_calibration_provenance_requires_authentic_complete_metadata(tmp_path):
    pcap = tmp_path / "reference.pcap"
    pcap.write_bytes(b"pcap")
    manifest = tmp_path / "calibration.json"
    manifest.write_text(
        json.dumps(_manifest(pcap, metadata={
            "packet_records_complete": True,
            "snaplen_truncated": False,
            "capture_drops": False,
        })),
        encoding="utf-8",
    )

    result = load_calibration_provenance(manifest, tmp_path)
    assert result["references"][0]["ground_truth_label"] == "NORMAL"


@pytest.mark.parametrize("metadata", [None, {}, {
    "packet_records_complete": True,
    "snaplen_truncated": False,
}])
def test_unknown_capture_metadata_rejects_calibration(tmp_path, metadata):
    pcap = tmp_path / "reference.pcap"
    pcap.write_bytes(b"pcap")
    manifest = tmp_path / "calibration.json"
    manifest.write_text(
        json.dumps(_manifest(pcap, metadata=metadata)),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="capture metadata"):
        load_calibration_provenance(manifest, tmp_path)


def test_checksum_mismatch_rejects_calibration(tmp_path):
    pcap = tmp_path / "reference.pcap"
    pcap.write_bytes(b"pcap")
    manifest = tmp_path / "calibration.json"
    data = _manifest(pcap, metadata={
        "packet_records_complete": True,
        "snaplen_truncated": False,
        "capture_drops": False,
    })
    data["references"][0]["sha256"] = "0" * 64
    manifest.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="SHA256"):
        load_calibration_provenance(manifest, tmp_path)


def test_ambiguous_label_rejects_calibration(tmp_path):
    pcap = tmp_path / "reference.pcap"
    pcap.write_bytes(b"pcap")
    manifest = tmp_path / "calibration.json"
    manifest.write_text(json.dumps(_manifest(
        pcap,
        label="UNKNOWN",
        metadata={
            "packet_records_complete": True,
            "snaplen_truncated": False,
            "capture_drops": False,
        },
    )), encoding="utf-8")
    with pytest.raises(ValueError, match="ground-truth"):
        load_calibration_provenance(manifest, tmp_path)


import base64
from datetime import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from netids import hybrid_provenance


def _signed_envelope(monkeypatch, *, private=None, event_id="capture-a-event-1", sequence=1):
    private = private or Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    fingerprint = hybrid_provenance.public_key_sha256(public)
    monkeypatch.setattr(hybrid_provenance, "PINNED_HYBRID_PRODUCER_PUBLIC_KEY_PEM", public)
    monkeypatch.setattr(hybrid_provenance, "PINNED_HYBRID_PRODUCER_SHA256", fingerprint)
    monkeypatch.setattr(hybrid_provenance, "PINNED_HYBRID_PRODUCER_IDENTITY", "producer-a")
    value = {"schema_version": "hybrid_telemetry_v1", "producer_identity": "producer-a", "capture_run_id": "capture-a", "telemetry_event_id": event_id, "sequence": sequence, "source_pcap_sha256": "a" * 64, "timestamp_provenance": {"first_timestamp": "2026-11-13T09:00:00+00:00", "last_timestamp": "2026-11-13T11:00:00+00:00"}, "producer_key_sha256": fingerprint, "payload": {"rst_evidence": {"capture_integrity": {"capture_complete": True}, "max_rst_count_per_window": 1}, "port_evidence": {"max_window_distinct_ports": 1}, "handshake_evidence": {"initial_syn_packets": 1, "flows_with_confirmed_handshake": 0, "flows_with_bidirectional_payload": 0}, "thresholds": {"min_unique_destination_ports": 1, "min_rst_count_per_window": 1, "max_handshake_failure_count": 1}}}
    value["signature"] = base64.b64encode(private.sign(hybrid_provenance.canonical_payload(value))).decode()
    return value


def test_signed_hybrid_envelope_is_verified(monkeypatch):
    value = _signed_envelope(monkeypatch)
    payload = hybrid_provenance.verify_envelope(value, expected_run_id="capture-a", event_time=datetime.fromisoformat("2026-11-13T10:00:00+00:00"), seen_capture_ids=set())
    assert set(payload) == {"rst_evidence", "port_evidence", "handshake_evidence", "thresholds"}


@pytest.mark.parametrize("mutation", [
    lambda value: value["payload"].update(rst_evidence={"tampered": True}),
    lambda value: value.update(producer_key_sha256="b" * 64),
    lambda value: value.update(signature=base64.b64encode(b"bad").decode()),
    lambda value: value.update(source_pcap_sha256="b" * 64),
    lambda value: value.update(timestamp_provenance={}),
    lambda value: value.update(payload={"rst_evidence": {}}),
])
def test_modified_or_incomplete_hybrid_envelope_is_rejected(monkeypatch, mutation):
    value = _signed_envelope(monkeypatch)
    mutation(value)
    with pytest.raises(ValueError):
        hybrid_provenance.verify_envelope(value, expected_run_id="capture-a", event_time=datetime.fromisoformat("2026-11-13T10:00:00+00:00"), seen_capture_ids=set())


def test_hybrid_replay_and_missing_trust_anchor_are_rejected(monkeypatch):
    value = _signed_envelope(monkeypatch)
    seen = set()
    event_time = datetime.fromisoformat("2026-11-13T10:00:00+00:00")
    hybrid_provenance.verify_envelope(value, expected_run_id="capture-a", event_time=event_time, seen_capture_ids=seen)
    with pytest.raises(ValueError, match="replay"):
        hybrid_provenance.verify_envelope(value, expected_run_id="capture-a", event_time=event_time, seen_capture_ids=seen)
    monkeypatch.setattr(hybrid_provenance, "PINNED_HYBRID_PRODUCER_PUBLIC_KEY_PEM", None)
    with pytest.raises(ValueError, match="trust anchor"):
        hybrid_provenance.verify_envelope(value, expected_run_id="capture-a", event_time=event_time, seen_capture_ids=set())


def test_multiple_events_from_one_capture_and_sequence_policy(monkeypatch):
    private = Ed25519PrivateKey.generate()
    first = _signed_envelope(monkeypatch, private=private, event_id="event-1", sequence=1)
    second = _signed_envelope(monkeypatch, private=private, event_id="event-2", sequence=2)
    state, sequences = set(), {}
    event_time = datetime.fromisoformat("2026-11-13T10:00:00+00:00")
    hybrid_provenance.verify_envelope(first, expected_run_id="capture-a", event_time=event_time, seen_capture_ids=state, last_sequences=sequences)
    hybrid_provenance.verify_envelope(second, expected_run_id="capture-a", event_time=event_time, seen_capture_ids=state, last_sequences=sequences)
    with pytest.raises(ValueError, match="replay"):
        hybrid_provenance.verify_envelope(second, expected_run_id="capture-a", event_time=event_time, seen_capture_ids=state, last_sequences=sequences)
    third = _signed_envelope(monkeypatch, private=private, event_id="event-3", sequence=2)
    with pytest.raises(ValueError, match="out of order"):
        hybrid_provenance.verify_envelope(third, expected_run_id="capture-a", event_time=event_time, seen_capture_ids=state, last_sequences=sequences)
