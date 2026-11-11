"""Create an independent encrypted Ed25519 keypair for one operator role.

Usage (run separately on owner Windows and replay VM1, NEVER share private PEM):
 python -m scripts.lifecycle_keys --role owner --private data/private/owner.pem --public data/private/owner.pub.pem
 python -m scripts.lifecycle_keys --role replay --private data/private/replay.pem --public data/private/replay.pub.pem
"""

from __future__ import annotations

import argparse
import getpass
import os
import stat
from pathlib import Path

from netids.lifecycle_ed25519 import generate_encrypted_keypair, public_key_fingerprint


def _exclusive(path: Path, payload: bytes) -> None:
    path = Path(path)
    if path.is_symlink() or path.exists():
        raise FileExistsError("Refusing to overwrite existing key material")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.parent.is_symlink():
        raise PermissionError("Private-key directory must not be a symlink")
    if os.name == "posix" and (stat.S_IMODE(path.parent.stat().st_mode) & 0o077):
        raise PermissionError("Key directory is accessible to group/other users")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name == "posix":
            os.chmod(path, 0o600)
    except Exception:
        path.unlink(missing_ok=True)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", choices=("owner", "replay"), required=True)
    parser.add_argument("--private", type=Path, required=True)
    parser.add_argument("--public", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.private.resolve() == args.public.resolve():
        parser.error("Public and private key paths must be different")
    if args.private.exists() or args.public.exists():
        parser.error("Key already exists; no overwrite")
    password = getpass.getpass(f"{args.role} private-key passphrase (>= 12 bytes): ").encode()
    confirm = getpass.getpass("Repeat passphrase: ").encode()
    if password != confirm:
        parser.error("Passphrases do not match")
    private_pem, public_pem = generate_encrypted_keypair(password)
    _exclusive(args.private, private_pem)
    try:
        _exclusive(args.public, public_pem)
    except Exception:
        args.private.unlink(missing_ok=True)
        raise
    print(f"Role: {args.role}")
    print(f"Ed25519 public-key fingerprint SHA256: {public_key_fingerprint(public_pem)}")
    print(f"Public key: {args.public}")
    print("Private key was created encrypted; keep it out of Git and other machines.")
    if os.name == "nt":
        print("Check Windows NTFS ACLs: only the owner should access the private PEM.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
