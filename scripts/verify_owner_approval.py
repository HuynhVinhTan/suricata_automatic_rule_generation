"""Verify an owner authorization using only a pinned Ed25519 public key."""
import argparse
from pathlib import Path
from backend.owner_approval_service import verify_owner_approval


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    args = parser.parse_args(argv)
    import json
    valid = verify_owner_approval(json.loads(args.record.read_text(encoding="utf-8")), args.signature.read_text(encoding="ascii").strip(), args.public_key)
    print("VALID" if valid else "INVALID")
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
