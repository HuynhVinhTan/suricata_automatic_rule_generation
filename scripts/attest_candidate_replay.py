"""Sign a verified ML candidate only after real isolated Suricata replay."""

from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path

from netids.candidate_replay import APPROVED_CASE_MANIFEST_SHA256, attest_candidate_replay


def _write_exclusive(path: Path, record: dict) -> None:
    if path.exists() or path.is_symlink():
        raise ValueError("Refusing to overwrite signed evidence")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
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
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--calibration", type=Path, required=True)
    parser.add_argument("--baseline-rules", type=Path, required=True)
    parser.add_argument("--case-manifest", type=Path, required=True)
    parser.add_argument("--isolated-yaml", type=Path, required=True)
    parser.add_argument("--isolated-root", type=Path, required=True)
    parser.add_argument("--replay-private", type=Path, required=True)
    parser.add_argument("--replay-public", type=Path, required=True)
    parser.add_argument("--suricata", default="/usr/bin/suricata")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        candidate = json.loads(args.candidate.read_text(encoding="utf-8"))
        if not isinstance(candidate, dict):
            raise ValueError("Candidate must be a JSON object")
        password = getpass.getpass("Candidate replay signing key passphrase: ").encode()
        evidence = attest_candidate_replay(
            candidate=candidate, artifact_dir=args.artifact_dir,
            calibration_manifest=args.calibration, baseline_rules=args.baseline_rules,
            case_manifest=args.case_manifest,
            expected_case_manifest_sha256=APPROVED_CASE_MANIFEST_SHA256,
            isolated_yaml=args.isolated_yaml, isolated_root=args.isolated_root,
            private_key_pem=args.replay_private.read_bytes(), private_key_password=password,
            replay_public_pem=args.replay_public.read_bytes(), suricata_binary=args.suricata,
        )
        _write_exclusive(args.output, evidence)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        parser.error(str(exc))
    print(f"Candidate replay attestation saved: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
