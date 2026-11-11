"""VM1 local-only replay signer; it executes Suricata, not a caller's success flags.

No network listener and no production service actions. Run with an owner-pinned
manifest SHA after the original rule, PCAP and isolated YAML are inspected.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path

from netids.lifecycle_ed25519 import verify_record
from netids.trusted_replay import attest_six_holdouts


def _exclusive_json(path: Path, record: dict) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(record, handle, indent=2, sort_keys=True, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--rule", type=Path, required=True)
    parser.add_argument("--isolated-yaml", type=Path, required=True)
    parser.add_argument("--isolated-root", type=Path, required=True)
    parser.add_argument("--replay-private", type=Path, required=True)
    parser.add_argument("--replay-public", type=Path, required=True)
    parser.add_argument("--suricata", default="/usr/bin/suricata")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output.exists() or args.output.is_symlink():
        parser.error("Refusing to overwrite signed evidence")
    password = getpass.getpass("VM1 replay signing key passphrase: ").encode()
    record = attest_six_holdouts(
        manifest_path=args.manifest,
        expected_manifest_sha256=args.manifest_sha256,
        rule_file=args.rule,
        isolated_yaml=args.isolated_yaml,
        isolated_root=args.isolated_root,
        private_key_pem=args.replay_private.read_bytes(),
        private_key_password=password,
        suricata_binary=args.suricata,
    )
    if not verify_record(
        record, args.replay_public.read_bytes(), domain="isolated-replay-v1"
    ):
        raise ValueError("Replay signer and pinned public key do not match")
    _exclusive_json(args.output, record)
    print("Six original replay sessions validated and Ed25519 attestation saved.")
    print(f"Output: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
