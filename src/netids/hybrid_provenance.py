"""Fail-closed provenance loading for hybrid Normal calibration."""

import json

from netids.lab_runtime import sha256


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
    if (
        not isinstance(thresholds, dict)
        or thresholds.get("method") != "max_complete_normal_reference_plus_one"
        or thresholds.get("final_holdout_used") is not False
    ):
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
        if (
            not isinstance(metadata, dict)
            or metadata.get("packet_records_complete") is not True
            or metadata.get("snaplen_truncated") is not False
            or metadata.get("capture_drops") is not False
        ):
            raise ValueError("Hybrid calibration capture metadata is unknown")
    return data
