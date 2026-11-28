"""Installed CLI entry points for the LAB_DEMO_ONLY G3 trust boundary."""

from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path

from netids.g3_lab_demo import (
    G3ReplayError,
    sign_lab_demo_record,
    verify_and_record_lab_demo,
)
from netids.lifecycle_ed25519 import generate_encrypted_keypair, public_key_fingerprint


def _reject_symlink_path(path: Path) -> None:
    if path.is_symlink():
        raise ValueError(f"refusing symlink path: {path}")
    for parent in path.parents:
        if parent == Path(parent.anchor):
            break
        if parent.is_symlink():
            raise ValueError(f"refusing symlink parent: {parent}")


def _write_exclusive(path: Path, data: bytes, mode: int) -> None:
    _reject_symlink_path(path)
    if path.exists():
        raise ValueError(f"refusing to overwrite existing file: {path}")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _reject_symlink_path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def provision_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.private_key == args.public_key:
        parser.error("private and public key paths must differ")
    password = getpass.getpass("VM2 LAB_DEMO_ONLY private-key passphrase: ").encode()
    confirmation = getpass.getpass("Repeat passphrase: ").encode()
    if password != confirmation:
        parser.error("passphrases did not match")
    private_pem, public_pem = generate_encrypted_keypair(password)
    _write_exclusive(args.private_key, private_pem, 0o600)
    try:
        _write_exclusive(args.public_key, public_pem, 0o644)
    except Exception:
        args.private_key.unlink(missing_ok=True)
        raise
    print(f"PUBLIC_KEY_FINGERPRINT={public_key_fingerprint(public_pem)}")
    print(f"PRIVATE_KEY={args.private_key}")
    print(f"PUBLIC_KEY={args.public_key}")
    return 0


def sign_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-record", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output.exists() or args.output.is_symlink():
        parser.error("output exists; refusing overwrite")
    record = json.loads(args.input_record.read_text(encoding="utf-8"))
    password = getpass.getpass("VM2 LAB_DEMO_ONLY signing passphrase: ").encode()
    envelope = sign_lab_demo_record(record, args.private_key.read_bytes(), password)
    _write_exclusive(args.output, (json.dumps(envelope, indent=2, sort_keys=True) + "\n").encode(), 0o600)
    return 0


def verify_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--envelope", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--pinned-fingerprint-file", type=Path, required=True)
    parser.add_argument("--sqlite", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output.exists() or args.output.is_symlink():
        parser.error("output exists; refusing overwrite")
    try:
        fingerprint = args.pinned_fingerprint_file.read_text(encoding="ascii").strip()
        result = verify_and_record_lab_demo(
            json.loads(args.envelope.read_text(encoding="utf-8")),
            args.public_key.read_bytes(),
            pinned_fingerprint=fingerprint,
            sqlite_path=args.sqlite,
        )
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError, G3ReplayError) as exc:
        print(f"G3_BLOCKED: {exc}")
        return 77
    _write_exclusive(args.output, (json.dumps(result, indent=2, sort_keys=True) + "\n").encode(), 0o600)
    return 0

