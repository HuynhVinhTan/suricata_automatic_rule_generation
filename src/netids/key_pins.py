"""Owner-reviewed public-key trust anchors for the one-time isolated experiment.

An operator must provision independent encrypted Ed25519 keypairs, verify
their fingerprints out-of-band, and commit ONLY the reviewed public-key
fingerprints below on this feature branch. Until then activation is blocked.

Never derive trust anchors from caller-provided JSON, private PCAPs, approval
records, command-line options, or mutable VM1 runtime directories.
"""

from __future__ import annotations

import re

from netids.lifecycle_ed25519 import public_key_fingerprint

# Provision and independently verify the role keys BEFORE setting these.
# These are intentionally invalid sentinels, NOT mock or demo public keys.
PINNED_REPLAY_ED25519_SHA256 = "b360fc9660513611a09287c9e6269c4bac4ac354ee85cecc0bbdbd4534f4d982"
# Candidate-specific replacement for the active frozen SID9103005 G5 path.
# The historical replay pin above remains exclusively for historical workflows.
PINNED_G5_FROZEN_REPLAY_ED25519_SHA256 = "77af3ee89e4b7a1cbb99369b19e244b0be70a44dfc745ab77a926d9ad98a7b92"
PINNED_OWNER_ED25519_SHA256 = "92b2fb2fffa9da9ac82011fca030b4d5d822046c1fbe6c375ee08d5237cc4de7"

_SHA = re.compile(r"^[0-9a-f]{64}$")


class TrustAnchorError(ValueError):
    """Missing or untrusted replay/owner Ed25519 public key."""


def require_pinned_replay_key(replay_public_pem: bytes) -> None:
    """Require the independently provisioned replay trust anchor."""
    if not _SHA.fullmatch(PINNED_REPLAY_ED25519_SHA256):
        raise TrustAnchorError("Replay trust anchor is not provisioned")
    try:
        fingerprint = public_key_fingerprint(replay_public_pem)
    except (ValueError, TypeError) as exc:
        raise TrustAnchorError("Invalid replay public-key PEM") from exc
    if fingerprint != PINNED_REPLAY_ED25519_SHA256:
        raise TrustAnchorError("Replay public-key fingerprint mismatch")


def require_pinned_frozen_g5_replay_key(replay_public_pem: bytes) -> None:
    """Require the candidate-specific replay anchor for frozen SID9103005 G5."""
    if not _SHA.fullmatch(PINNED_G5_FROZEN_REPLAY_ED25519_SHA256):
        raise TrustAnchorError("Frozen G5 replay trust anchor is not provisioned")
    try:
        fingerprint = public_key_fingerprint(replay_public_pem)
    except (ValueError, TypeError) as exc:
        raise TrustAnchorError("Invalid frozen G5 replay public-key PEM") from exc
    if fingerprint != PINNED_G5_FROZEN_REPLAY_ED25519_SHA256:
        raise TrustAnchorError("Frozen G5 replay public-key fingerprint mismatch")


def require_pinned_frozen_g5_role_keys(
    replay_public_pem: bytes,
    owner_public_pem: bytes,
    runtime_public_pem: bytes,
) -> None:
    """Require frozen G5 replay/owner pins and independent runtime signing role."""
    if (
        not _SHA.fullmatch(PINNED_G5_FROZEN_REPLAY_ED25519_SHA256)
        or not _SHA.fullmatch(PINNED_OWNER_ED25519_SHA256)
        or PINNED_G5_FROZEN_REPLAY_ED25519_SHA256 == PINNED_OWNER_ED25519_SHA256
    ):
        raise TrustAnchorError("Frozen G5 Ed25519 trust anchors are not provisioned")
    require_pinned_frozen_g5_replay_key(replay_public_pem)
    try:
        owner_fingerprint = public_key_fingerprint(owner_public_pem)
        runtime_fingerprint = public_key_fingerprint(runtime_public_pem)
    except (ValueError, TypeError) as exc:
        raise TrustAnchorError("Invalid frozen G5 role public-key PEM") from exc
    if owner_fingerprint != PINNED_OWNER_ED25519_SHA256:
        raise TrustAnchorError("Frozen G5 owner public-key fingerprint mismatch")
    if runtime_fingerprint in {
        PINNED_G5_FROZEN_REPLAY_ED25519_SHA256,
        PINNED_OWNER_ED25519_SHA256,
    }:
        raise TrustAnchorError("Frozen G5 role keys must be independent")


def require_pinned_role_keys(replay_public_pem: bytes, owner_public_pem: bytes) -> None:
    """Fail closed until both independently reviewed role fingerprints match."""
    if (
        not _SHA.fullmatch(PINNED_REPLAY_ED25519_SHA256)
        or not _SHA.fullmatch(PINNED_OWNER_ED25519_SHA256)
        or PINNED_REPLAY_ED25519_SHA256 == PINNED_OWNER_ED25519_SHA256
    ):
        raise TrustAnchorError(
            "One-time isolated lab Ed25519 trust anchors are not provisioned"
        )
    try:
        replay_fingerprint = public_key_fingerprint(replay_public_pem)
        owner_fingerprint = public_key_fingerprint(owner_public_pem)
    except (ValueError, TypeError) as exc:
        raise TrustAnchorError("Invalid public-key PEM") from exc
    if (
        replay_fingerprint != PINNED_REPLAY_ED25519_SHA256
        or owner_fingerprint != PINNED_OWNER_ED25519_SHA256
    ):
        raise TrustAnchorError("Trusted operator-reviewed Ed25519 fingerprint mismatch")
