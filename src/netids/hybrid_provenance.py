"""Fail-closed verification boundary for packet-level Hybrid telemetry.

The production trust anchor is deliberately unprovisioned in this repository.
An operator-owned deployment must provision the public key and fingerprint out
of band; caller-supplied keys and ``adapter_verified`` claims are never trusted.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from netids.lab_runtime import sha256


PINNED_HYBRID_PRODUCER_PUBLIC_KEY_PEM: bytes | None = None
PINNED_HYBRID_PRODUCER_SHA256: str | None = None


def canonical_payload(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def public_key_sha256(public_key_pem: bytes) -> str:
    key = serialization.load_pem_public_key(public_key_pem)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Hybrid producer key must be Ed25519")
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("Hybrid timestamp provenance is required")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.utcoffset() is None:
        raise ValueError("Hybrid timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def verify_envelope(
    envelope: dict[str, Any],
    *,
    expected_run_id: str,
    event_time: datetime,
    seen_capture_ids: set[str],
    last_sequences: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Return the exact trusted evidence payload or raise ``ValueError``."""
    if PINNED_HYBRID_PRODUCER_PUBLIC_KEY_PEM is None or not PINNED_HYBRID_PRODUCER_SHA256:
        raise ValueError("Hybrid producer trust anchor is not provisioned")
    required = {
        "schema_version", "producer_identity", "capture_run_id", "telemetry_event_id", "sequence",
        "source_pcap_sha256",
        "timestamp_provenance", "producer_key_sha256", "payload", "signature",
    }
    if not required.issubset(envelope):
        raise ValueError("Incomplete Hybrid trust envelope")
    if envelope["schema_version"] != "hybrid_telemetry_v1":
        raise ValueError("Unsupported Hybrid telemetry schema")
    if envelope["producer_key_sha256"] != PINNED_HYBRID_PRODUCER_SHA256:
        raise ValueError("Hybrid producer key fingerprint mismatch")
    if public_key_sha256(PINNED_HYBRID_PRODUCER_PUBLIC_KEY_PEM) != PINNED_HYBRID_PRODUCER_SHA256:
        raise ValueError("Pinned Hybrid producer key is inconsistent")
    if not isinstance(envelope["telemetry_event_id"], str) or not envelope["telemetry_event_id"].strip():
        raise ValueError("Hybrid telemetry event identity is required")
    if not isinstance(envelope["sequence"], int) or envelope["sequence"] < 0:
        raise ValueError("Hybrid telemetry sequence is invalid")
    if envelope["telemetry_event_id"] in seen_capture_ids:
        raise ValueError("Hybrid telemetry event replay detected")
    if last_sequences is not None and envelope["sequence"] <= last_sequences.get(envelope["capture_run_id"], -1):
        raise ValueError("Hybrid telemetry sequence is out of order")
    if envelope["capture_run_id"] != expected_run_id:
        raise ValueError("Hybrid capture/run identity mismatch")
    if not isinstance(envelope["producer_identity"], str) or not envelope["producer_identity"]:
        raise ValueError("Hybrid producer identity is required")
    if not re.fullmatch(r"[0-9a-f]{64}", str(envelope["source_pcap_sha256"])):
        raise ValueError("Hybrid PCAP hash is invalid")
    provenance = envelope["timestamp_provenance"]
    if not isinstance(provenance, dict):
        raise ValueError("Hybrid timestamp provenance is invalid")
    lower, upper = _timestamp(provenance.get("first_timestamp")), _timestamp(provenance.get("last_timestamp"))
    if lower > upper or not lower <= event_time <= upper:
        raise ValueError("Hybrid timestamp is outside the signed capture range")
    payload = envelope["payload"]
    if not isinstance(payload, dict) or set(payload) != {"rst_evidence", "port_evidence", "handshake_evidence", "thresholds"}:
        raise ValueError("Hybrid evidence payload is incomplete")
    try:
        signature = base64.b64decode(envelope["signature"], validate=True)
        key = serialization.load_pem_public_key(PINNED_HYBRID_PRODUCER_PUBLIC_KEY_PEM)
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("Invalid pinned Hybrid producer key")
        signed = {key: envelope[key] for key in required if key != "signature"}
        key.verify(signature, canonical_payload(signed))
    except (ValueError, InvalidSignature, KeyError) as exc:
        raise ValueError("Hybrid telemetry signature verification failed") from exc
    seen_capture_ids.add(envelope["telemetry_event_id"])
    if last_sequences is not None:
        last_sequences[envelope["capture_run_id"]] = envelope["sequence"]
    return payload


def load_calibration_provenance(manifest_path, private_root):
    manifest_path = manifest_path.resolve(strict=True)
    private_root = private_root.resolve(strict=True)
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    if data.get("schema_version") != "hybrid_normal_calibration_v1":
        raise ValueError("Unsupported hybrid calibration provenance schema")
    if data.get("feature_definition") != "TCP SYN destination-port sliding diversity":
        raise ValueError("Invalid hybrid calibration feature definition")
    if data.get("window_seconds") != 60:
        raise ValueError("Invalid hybrid calibration window")
    thresholds = data.get("threshold_provenance")
    if (not isinstance(thresholds, dict) or thresholds.get("method") != "max_complete_normal_reference_plus_one" or
            thresholds.get("final_holdout_used") is not False):
        raise ValueError("Invalid hybrid threshold provenance")
    references = data.get("references")
    if not isinstance(references, list) or not references:
        raise ValueError("Hybrid calibration references are required")
    for reference in references:
        if not isinstance(reference, dict):
            raise ValueError("Invalid hybrid calibration reference")
        path = private_root / reference.get("path", "")
        try:
            path.resolve(strict=True).relative_to(private_root)
        except (OSError, ValueError) as exc:
            raise ValueError("Hybrid calibration path escapes private root") from exc
        if not path.is_file() or sha256(path) != reference.get("sha256"):
            raise ValueError("Hybrid calibration PCAP SHA256 mismatch")
        if reference.get("ground_truth_label") != "NORMAL":
            raise ValueError("Hybrid calibration ground-truth label is ambiguous")
        if reference.get("source_ipv4") != "192.168.10.20" or reference.get("destination_ipv4") != "192.168.10.10":
            raise ValueError("Hybrid calibration flow endpoints are invalid")
        if not isinstance(reference.get("ground_truth_source"), str) or not reference["ground_truth_source"].strip():
            raise ValueError("Hybrid calibration ground-truth source is required")
        metadata = reference.get("capture_metadata")
        if (not isinstance(metadata, dict) or metadata.get("packet_records_complete") is not True or
                metadata.get("snaplen_truncated") is not False or metadata.get("capture_drops") is not False):
            raise ValueError("Hybrid calibration capture metadata is unknown")
    return data
