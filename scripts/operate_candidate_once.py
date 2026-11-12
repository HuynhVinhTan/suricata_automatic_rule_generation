"""Execute one approved candidate activation and mandatory verified rollback."""

from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path

from scripts.operate_isolated_once import execute_candidate_one_time


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "candidate-file", "replay-attestation-file", "owner-approval-file",
        "replay-public-file", "owner-public-file", "production-yaml",
        "production-rules", "isolated-yaml", "isolated-root", "attack-pcap",
        "attack-sha256", "normal-pcap", "normal-sha256", "audit-path",
        "replay-private-file", "evidence-output", "failure-output",
    ):
        parser.add_argument("--" + name, required=True, type=Path if not name.endswith("sha256") else str)
    args = parser.parse_args(argv)
    if args.evidence_output.exists() or args.evidence_output.is_symlink():
        parser.error("Evidence already exists; never overwrite")
    password = getpass.getpass("Candidate runtime signing key passphrase: ").encode()
    evidence = execute_candidate_one_time(
        candidate_file=args.candidate_file,
        replay_attestation_file=args.replay_attestation_file,
        owner_approval_file=args.owner_approval_file,
        replay_public_file=args.replay_public_file,
        owner_public_file=args.owner_public_file,
        production_yaml=args.production_yaml, production_rules=args.production_rules,
        isolated_yaml=args.isolated_yaml, isolated_root=args.isolated_root,
        attack_pcap=args.attack_pcap, attack_sha256=args.attack_sha256,
        normal_pcap=args.normal_pcap, normal_sha256=args.normal_sha256,
        audit_path=args.audit_path, replay_private_pem=args.replay_private_file.read_bytes(),
        failure_path=args.failure_output, replay_private_password=password,
    )
    args.evidence_output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(args.evidence_output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(evidence, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    print(f"Candidate runtime evidence saved: {args.evidence_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
