"""Verify an Ed25519 replay attestation with a pinned public key."""
import argparse
from pathlib import Path
from backend.replay_attestation_service import verify_replay_attestation


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    args = parser.parse_args(argv)
    valid = verify_replay_attestation(args.record, args.signature, args.public_key)
    print("VALID" if valid else "INVALID")
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
