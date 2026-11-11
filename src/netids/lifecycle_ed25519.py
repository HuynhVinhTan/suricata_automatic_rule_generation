"""Ed25519 trust envelope for owner approval and verified isolated replay.

Private keys are encrypted and deliberately never stored in the repository.
The owner and replay roles MUST use independently generated keypairs. The
signature authenticates the attester, not the truth of unverified claims:
trusted signing frontends must check original evidence before signing.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

DOMAINS = frozenset({
    "isolated-replay-v1",
    "isolated-owner-approval-v1",
    "isolated-runtime-v1",
})
_FIELD = "attestation_ed25519"
_ALGO = "ed25519-v1"
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


def _canonical(record: Mapping) -> bytes:
    return json.dumps(
        record, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _signed_bytes(record: Mapping, domain: str) -> bytes:
    if domain not in DOMAINS:
        raise ValueError("Invalid attestation domain")
    return b"suricata-ai-ed25519-v1\0" + domain.encode("ascii") + b"\0" + _canonical(record)


def generate_encrypted_keypair(password: bytes) -> tuple[bytes, bytes]:
    """Generate encrypted PKCS8 PEM and public PEM for one independent role."""
    if not isinstance(password, bytes) or len(password) < 12:
        raise ValueError("A passphrase of at least 12 bytes is required")
    key = Ed25519PrivateKey.generate()
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password),
    )
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def public_key_fingerprint(public_pem: bytes) -> str:
    key = serialization.load_pem_public_key(public_pem)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Not an Ed25519 public key")
    raw = key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()


def sign_record(
    record: Mapping,
    private_pem: bytes,
    password: bytes,
    *,
    domain: str,
) -> dict:
    """Sign a verified, canonical JSON record. No caller-supplied signatures."""
    if not isinstance(record, Mapping) or any(
        str(key).startswith("attestation_") for key in record
    ):
        raise ValueError("Attestation fields must be created by the signer")
    key = serialization.load_pem_private_key(private_pem, password=password)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Not an Ed25519 private key")
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    payload = dict(record)
    payload.update({
        "attestation_algorithm": _ALGO,
        "attestation_key_sha256": public_key_fingerprint(public_pem),
    })
    sig = key.sign(_signed_bytes(payload, domain))
    return {**payload, _FIELD: base64.b64encode(sig).decode("ascii")}


def verify_record(record: Mapping, public_pem: bytes, *, domain: str) -> bool:
    """Verify domain, canonical bytes, fingerprint and pinned public key."""
    if not isinstance(record, Mapping) or domain not in DOMAINS:
        return False
    if record.get("attestation_algorithm") != _ALGO:
        return False
    fingerprint = record.get("attestation_key_sha256")
    signature = record.get(_FIELD)
    if not isinstance(fingerprint, str) or not _DIGEST.fullmatch(fingerprint):
        return False
    if not isinstance(signature, str):
        return False
    try:
        public = serialization.load_pem_public_key(public_pem)
        if not isinstance(public, Ed25519PublicKey):
            return False
        if public_key_fingerprint(public_pem) != fingerprint:
            return False
        sig = base64.b64decode(signature, validate=True)
        if len(sig) != 64:
            return False
        signed = dict(record)
        del signed[_FIELD]
        public.verify(sig, _signed_bytes(signed, domain))
        return True
    except (TypeError, KeyError, ValueError, UnicodeError, InvalidSignature):
        return False


def sha256_file(path) -> str:
    """Read-only streaming SHA256 for immutable private artifacts."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()
