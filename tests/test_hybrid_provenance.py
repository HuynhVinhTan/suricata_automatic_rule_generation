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
