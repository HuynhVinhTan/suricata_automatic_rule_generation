"""Activation trust anchors: public-key pinning, not caller-supplied trust."""

import pytest

from netids import key_pins
from netids.lifecycle_ed25519 import (
    generate_encrypted_keypair,
    public_key_fingerprint,
)


def _public():
    return generate_encrypted_keypair(
        b"synthetic-owner-replay-trust-test-password"
    )[1]


def test_unprovisioned_public_keys_block_any_real_operation(monkeypatch):
    monkeypatch.setattr(key_pins, "PINNED_REPLAY_ED25519_SHA256", "UNPROVISIONED")
    monkeypatch.setattr(key_pins, "PINNED_OWNER_ED25519_SHA256", "UNPROVISIONED")
    with pytest.raises(key_pins.TrustAnchorError, match="not provisioned"):
        key_pins.require_pinned_role_keys(_public(), _public())


def test_provisioned_keys_still_reject_unrelated_test_keys():
    with pytest.raises(key_pins.TrustAnchorError, match="mismatch"):
        key_pins.require_pinned_role_keys(_public(), _public())


def test_separately_pinned_owner_and_replay_public_keys_are_required(monkeypatch):
    replay = _public()
    owner = _public()
    monkeypatch.setattr(
        key_pins, "PINNED_REPLAY_ED25519_SHA256",
        public_key_fingerprint(replay),
    )
    monkeypatch.setattr(
        key_pins, "PINNED_OWNER_ED25519_SHA256",
        public_key_fingerprint(owner),
    )
    key_pins.require_pinned_role_keys(replay, owner)
    with pytest.raises(key_pins.TrustAnchorError, match="mismatch"):
        key_pins.require_pinned_role_keys(_public(), owner)
    with pytest.raises(key_pins.TrustAnchorError, match="mismatch"):
        key_pins.require_pinned_role_keys(replay, _public())


def test_same_public_key_for_both_roles_is_forbidden(monkeypatch):
    public = _public()
    fingerprint = public_key_fingerprint(public)
    monkeypatch.setattr(key_pins, "PINNED_REPLAY_ED25519_SHA256", fingerprint)
    monkeypatch.setattr(key_pins, "PINNED_OWNER_ED25519_SHA256", fingerprint)
    with pytest.raises(key_pins.TrustAnchorError, match="not provisioned"):
        key_pins.require_pinned_role_keys(public, public)


def test_frozen_g5_replay_anchor_is_candidate_specific_and_not_historical(monkeypatch):
    assert key_pins.PINNED_G5_FROZEN_REPLAY_ED25519_SHA256 == (
        "77af3ee89e4b7a1cbb99369b19e244b0be70a44dfc745ab77a926d9ad98a7b92"
    )
    assert key_pins.PINNED_G5_FROZEN_REPLAY_ED25519_SHA256 != (
        key_pins.PINNED_REPLAY_ED25519_SHA256
    )
    replay = _public()
    monkeypatch.setattr(
        key_pins,
        "PINNED_G5_FROZEN_REPLAY_ED25519_SHA256",
        public_key_fingerprint(replay),
    )
    key_pins.require_pinned_frozen_g5_replay_key(replay)
    with pytest.raises(key_pins.TrustAnchorError, match="mismatch"):
        key_pins.require_pinned_frozen_g5_replay_key(_public())


def test_frozen_g5_roles_require_new_replay_pin_owner_pin_and_distinct_runtime(monkeypatch):
    replay = _public()
    owner = _public()
    runtime = _public()
    monkeypatch.setattr(
        key_pins,
        "PINNED_G5_FROZEN_REPLAY_ED25519_SHA256",
        public_key_fingerprint(replay),
    )
    monkeypatch.setattr(
        key_pins,
        "PINNED_OWNER_ED25519_SHA256",
        public_key_fingerprint(owner),
    )
    key_pins.require_pinned_frozen_g5_role_keys(replay, owner, runtime)
    with pytest.raises(key_pins.TrustAnchorError, match="mismatch"):
        key_pins.require_pinned_frozen_g5_role_keys(_public(), owner, runtime)
    with pytest.raises(key_pins.TrustAnchorError, match="mismatch"):
        key_pins.require_pinned_frozen_g5_role_keys(replay, _public(), runtime)
    with pytest.raises(key_pins.TrustAnchorError, match="independent"):
        key_pins.require_pinned_frozen_g5_role_keys(replay, owner, replay)
    with pytest.raises(key_pins.TrustAnchorError, match="independent"):
        key_pins.require_pinned_frozen_g5_role_keys(replay, owner, owner)
