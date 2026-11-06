"""Bounded batch worker for the review-only lab AI pipeline."""

from __future__ import annotations

import argparse
import hashlib
import json
import uuid
from datetime import datetime, timezone
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from netids.pipeline import run as run_pipeline

WORKER_SCHEMA_VERSION = "pcap_ai_worker_v0_1"
MAX_PCAP_SIZE_BYTES = 2 * 1024 * 1024 * 1024
DEFAULT_ES_INDEX = "suricata-ai-summary"

STATUS_COMPATIBILITY = {
    "no_candidate": "no_candidate",
    "needs_review": "needs_review",
    "rejected_known_false_positive": "rejected_known_false_positive",
    "rejected_validation_failure": "rejected_validation_failure",
    "validated_for_review": "validated_for_review",
    "NO_CANDIDATE": "no_candidate",
    "NEEDS_REVIEW": "needs_review",
    "REJECTED_KNOWN_FALSE_POSITIVE": "rejected_known_false_positive",
    "REJECTED_VALIDATION_FAILURE": "rejected_validation_failure",
    "VALIDATED_FOR_REVIEW": "validated_for_review",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalize_ipv4(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be an IPv4 string")
    try:
        return str(IPv4Address(value))
    except ValueError as exc:  # pragma: no cover - defensive
        raise ValueError(f"Invalid IPv4 for {field_name}: {value}") from exc


def normalize_review_status(value: Any) -> str:
    if value is None:
        return "no_candidate"
    normalized = str(value).strip()
    if normalized == "":
        return "no_candidate"
    mapped = STATUS_COMPATIBILITY.get(normalized)
    if mapped is not None:
        return mapped
    lowered = normalized.lower().replace(" ", "_")
    return STATUS_COMPATIBILITY.get(lowered, lowered)


def build_manifest(
    *,
    pcap: Path,
    src: str,
    dst: str,
    run_id: Optional[str] = None,
    capture_metadata: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    source_ip = normalize_ipv4(src, "source_ipv4")
    destination_ip = normalize_ipv4(dst, "destination_ipv4")
    manifest = {
        "schema_version": WORKER_SCHEMA_VERSION,
        "pcap_sha256": sha256_file(pcap),
        "source_ipv4": source_ip,
        "destination_ipv4": destination_ip,
        "run_id": run_id or uuid.uuid4().hex,
        "capture_metadata": dict(capture_metadata or {}),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    return manifest


def load_manifest(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Manifest not found: {path}")
    with path.open("r", encoding="utf-8") as stream:
        manifest = json.load(stream)
    if not isinstance(manifest, dict):
        raise ValueError("Manifest must decode to a JSON object")
    return manifest


def validate_manifest(
    manifest: Mapping[str, Any],
    *,
    pcap_path: Path,
    src: str,
    dst: str,
) -> Dict[str, Any]:
    if not isinstance(manifest, Mapping):
        raise ValueError("Manifest must be a JSON object")

    schema_version = manifest.get("schema_version")
    if schema_version != WORKER_SCHEMA_VERSION:
        raise ValueError(
            "Unsupported manifest schema_version; expected "
            f"{WORKER_SCHEMA_VERSION}"
        )

    required = {
        "pcap_sha256",
        "source_ipv4",
        "destination_ipv4",
        "run_id",
    }
    missing = sorted(required - set(manifest))
    if missing:
        raise ValueError(f"Manifest missing required fields: {missing}")

    expected_sha = sha256_file(pcap_path).lower()
    if str(manifest["pcap_sha256"]).lower() != expected_sha:
        raise ValueError("Manifest PCAP SHA256 does not match the input file")

    expected_src = normalize_ipv4(src, "source_ipv4")
    expected_dst = normalize_ipv4(dst, "destination_ipv4")
    if normalize_ipv4(manifest["source_ipv4"], "source_ipv4") != expected_src:
        raise ValueError("Manifest source IPv4 does not match the worker input")
    if normalize_ipv4(manifest["destination_ipv4"], "destination_ipv4") != expected_dst:
        raise ValueError("Manifest destination IPv4 does not match the worker input")

    if not manifest.get("run_id"):
        raise ValueError("Manifest run_id is required")

    return dict(manifest)


def _safe_summary_fields(summary: Mapping[str, Any]) -> Dict[str, Any]:
    safe = {
        "schema_version": summary.get("schema_version"),
        "run_id": summary.get("run_id"),
        "status": summary.get("status"),
        "review_status": summary.get("review_status"),
        "pcap_sha256": summary.get("pcap_sha256"),
        "source_ipv4": summary.get("source_ipv4"),
        "destination_ipv4": summary.get("destination_ipv4"),
        "deployable": summary.get("deployable"),
        "deployed": summary.get("deployed"),
        "generated_at": summary.get("generated_at"),
        "error": summary.get("error"),
    }
    return {key: value for key, value in safe.items() if value is not None}


def write_elasticsearch_summary(
    summary: Mapping[str, Any],
    destination: Path,
    *,
    index: str = DEFAULT_ES_INDEX,
) -> Path:
    payload = dict(_safe_summary_fields(summary))
    payload.setdefault("_index", index)
    payload.setdefault("ai_summary_version", "v1")
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return destination


def _read_json_if_present(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    try:
        with path.open("r", encoding="utf-8") as stream:
            payload = json.load(stream)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def run_worker(
    *,
    pcap: Path,
    src: str,
    dst: str,
    private_root: Path,
    output_dir: Path,
    expected_sha: Optional[str] = None,
    manifest_path: Optional[Path] = None,
    run_id: Optional[str] = None,
    processor: Optional[Any] = None,
) -> Dict[str, Any]:
    pcap = Path(pcap)
    private_root = Path(private_root)
    output_dir = Path(output_dir)

    if not pcap.exists():
        raise FileNotFoundError(f"PCAP not found: {pcap}")

    if pcap.stat().st_size > MAX_PCAP_SIZE_BYTES:
        raise ValueError("PCAP exceeds the safe local prototype size limit")

    source_ip = normalize_ipv4(src, "source_ipv4")
    destination_ip = normalize_ipv4(dst, "destination_ipv4")
    if source_ip == destination_ip:
        raise ValueError("Source and destination IPv4 addresses must differ")

    private_root = private_root.resolve()
    output_dir = output_dir.resolve()
    if not output_dir.is_relative_to(private_root):
        raise ValueError("Output directory must remain inside the private_root")

    if output_dir.exists():
        raise FileExistsError(
            "Output directory already exists; refusing overwrite"
        )

    manifest = build_manifest(
        pcap=pcap,
        src=source_ip,
        dst=destination_ip,
        run_id=run_id,
    )
    if manifest_path is not None:
        validated = validate_manifest(
            load_manifest(manifest_path),
            pcap_path=pcap,
            src=source_ip,
            dst=destination_ip,
        )
        manifest.update(validated)

    final_expected_sha = (expected_sha or sha256_file(pcap)).lower()
    if manifest.get("pcap_sha256", final_expected_sha).lower() != final_expected_sha:
        raise ValueError("Manifest checksum does not match the PCAP input")

    final_run_id = str(manifest.get("run_id") or run_id or uuid.uuid4().hex)
    output_dir = output_dir if output_dir.name else private_root / "lab-runs" / final_run_id
    if output_dir.exists():
        raise FileExistsError("Output directory already exists; refusing overwrite")

    processor_fn = processor or run_pipeline
    summary = {
        "schema_version": WORKER_SCHEMA_VERSION,
        "run_id": final_run_id,
        "pcap_sha256": final_expected_sha,
        "source_ipv4": source_ip,
        "destination_ipv4": destination_ip,
        "status": "running",
        "review_status": "no_candidate",
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    try:
        processor_fn(
            str(pcap),
            final_expected_sha,
            source_ip,
            destination_ip,
            private_root,
            output_dir,
        )
        summary["status"] = "succeeded"
    except Exception as exc:  # pragma: no cover - exercised via tests
        summary["status"] = "failed"
        summary["error"] = str(exc)

    review = _read_json_if_present(output_dir / "review.json")
    if review is not None:
        summary["review_status"] = normalize_review_status(review.get("status"))
        summary["deployable"] = bool(review.get("deployable") is True)
        summary["deployed"] = bool(review.get("deployed") is True)
        summary["rule_generated_in_this_run"] = bool(
            review.get("rule_generated_in_this_run") is True
        )
        summary["model_sha256"] = review.get("model_sha256")
        summary["generated_rule"] = review.get("generated_rule")
    elif summary["status"] == "succeeded":
        summary["review_status"] = "no_candidate"

    summary["output_dir"] = str(output_dir)
    summary["private_root"] = str(private_root)
    summary["schema_version"] = WORKER_SCHEMA_VERSION
    with (output_dir / "worker_summary.json").open("w", encoding="utf-8") as stream:
        json.dump(summary, stream, indent=2, ensure_ascii=False)
        stream.write("\n")
    return summary


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--src", required=True)
    parser.add_argument("--dst", required=True)
    parser.add_argument(
        "--private-root",
        type=Path,
        default=Path("data/private"),
    )
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--expected-sha256")
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--run-id")
    parser.add_argument("--es-output", type=Path)
    args = parser.parse_args(argv)

    try:
        summary = run_worker(
            pcap=args.pcap,
            src=args.src,
            dst=args.dst,
            private_root=args.private_root,
            output_dir=args.out_dir,
            expected_sha=args.expected_sha256,
            manifest_path=args.manifest,
            run_id=args.run_id,
        )
    except Exception as exc:  # pragma: no cover - CLI failure path
        payload = {
            "schema_version": WORKER_SCHEMA_VERSION,
            "status": "failed",
            "error": str(exc),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        if args.es_output is not None:
            write_elasticsearch_summary(payload, args.es_output)
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 1

    if args.es_output is not None:
        write_elasticsearch_summary(summary, args.es_output)

    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
