"""Verification-only HMAC envelope for trusted lab evidence and owner authorization.

Keys must come from separate, trusted private sources, not from candidate artifacts.
This module does not mint approvals or assert that a replay actually occurred.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re

_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DOMAINS = frozenset({"isolated-replay-v1", "isolated-owner-approval-v1"})


def verify_attestation(record: dict, secret: bytes | None, *, domain: str) -> bool:
    """Check exact canonical bytes and domain-separated authentication.

    This only proves that a holder of the private key authenticated the record.
    Actual Suricata replay and owner identity must be independently established
    by the trusted signing process; caller booleans alone are not proof.
    """
    if (
        not isinstance(record, dict)
        or not isinstance(secret, bytes)
        or len(secret) < 32
        or domain not in _DOMAINS
    ):
        return False
    signature = record.get("attestation_hmac")
    if not isinstance(signature, str) or not _HEX_SHA256.fullmatch(signature):
        return False
    content = {key: value for key, value in record.items() if key != "attestation_hmac"}
    try:
        serialized = json.dumps(
            content, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        return False
    payload = b"suricata-ai:" + domain.encode("ascii") + b"\0" + serialized
    expected = hmac.new(secret, payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)
