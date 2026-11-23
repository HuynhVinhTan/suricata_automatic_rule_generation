"""Build one evidence-derived LAB_DEMO_ONLY record without signing it."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from netids.g3_lab_demo import build_lab_demo_record_from_evidence


def _write_exclusive(path: Path, record: dict) -> None:
    if path.exists() or path.is_symlink():
        raise ValueError(f"refusing to overwrite existing record: {path}")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    old_umask = os.umask(0o077)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    finally:
        os.umask(old_umask)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(record, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture-id", required=True)
    parser.add_argument("--generator-id", required=True)
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--native-manifest", type=Path, required=True)
    parser.add_argument("--ready-marker", type=Path, required=True)
    parser.add_argument("--generator-json", type=Path, required=True)
    parser.add_argument("--expected-pcap-sha256", required=True)
    parser.add_argument("--expected-generator-sha256", required=True)
    parser.add_argument("--g3-run-id", required=True)
    parser.add_argument("--event-id", required=True)
    parser.add_argument("--sequence", type=int, required=True)
    parser.add_argument("--nonce", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    record = build_lab_demo_record_from_evidence(
        capture_id=args.capture_id,
        generator_id=args.generator_id,
        pcap=args.pcap,
        native_manifest=args.native_manifest,
        ready_marker=args.ready_marker,
        generator_json=args.generator_json,
        expected_pcap_sha256=args.expected_pcap_sha256,
        expected_generator_sha256=args.expected_generator_sha256,
        g3_run_id=args.g3_run_id,
        event_id=args.event_id,
        sequence=args.sequence,
        nonce=args.nonce,
    )
    _write_exclusive(args.output, record)
    print(json.dumps({"status": "built", "output": str(args.output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
