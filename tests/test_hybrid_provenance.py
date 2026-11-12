import base64
from datetime import datetime

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from netids import hybrid_provenance


def envelope(monkeypatch):
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    fingerprint = hybrid_provenance.public_key_sha256(public)
    monkeypatch.setattr(hybrid_provenance, "PINNED_HYBRID_PRODUCER_PUBLIC_KEY_PEM", public)
    monkeypatch.setattr(hybrid_provenance, "PINNED_HYBRID_PRODUCER_SHA256", fingerprint)
    value = {
        "schema_version": "hybrid_telemetry_v1", "producer_identity": "producer-a",
        "capture_run_id": "capture-a", "source_pcap_sha256": "a" * 64,
        "timestamp_provenance": {"first_timestamp": "2026-11-13T09:00:00+00:00", "last_timestamp": "2026-11-13T11:00:00+00:00"},
        "producer_key_sha256": fingerprint,
        "payload": {"rst_evidence": {}, "port_evidence": {}, "handshake_evidence": {}, "thresholds": {}},
    }
    value["signature"] = base64.b64encode(private.sign(hybrid_provenance.canonical_payload(value))).decode()
    return value


def test_signed_hybrid_envelope_is_verified(monkeypatch):
    value = envelope(monkeypatch)
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
    value = envelope(monkeypatch)
    mutation(value)
    with pytest.raises(ValueError):
        hybrid_provenance.verify_envelope(value, expected_run_id="capture-a", event_time=datetime.fromisoformat("2026-11-13T10:00:00+00:00"), seen_capture_ids=set())


def test_hybrid_replay_and_missing_trust_anchor_are_rejected(monkeypatch):
    value = envelope(monkeypatch)
    seen = set()
    event_time = datetime.fromisoformat("2026-11-13T10:00:00+00:00")
    hybrid_provenance.verify_envelope(value, expected_run_id="capture-a", event_time=event_time, seen_capture_ids=seen)
    with pytest.raises(ValueError, match="replay"):
        hybrid_provenance.verify_envelope(value, expected_run_id="capture-a", event_time=event_time, seen_capture_ids=seen)
    monkeypatch.setattr(hybrid_provenance, "PINNED_HYBRID_PRODUCER_PUBLIC_KEY_PEM", None)
    with pytest.raises(ValueError, match="trust anchor"):
        hybrid_provenance.verify_envelope(value, expected_run_id="capture-a", event_time=event_time, seen_capture_ids=set())
