"""Strict reviewed rule artifact provenance; no PCAP, VM or Suricata required."""

import hashlib

import pytest

from netids.trusted_replay import ReplayGateError, verify_pinned_rule_artifact


RULE = 'alert tcp any any -> any any (msg:"synthetic"; sid:9103999; rev:1;)'
RULE_SHA = hashlib.sha256(RULE.encode("utf-8")).hexdigest()


def test_rule_text_hash_differs_from_original_file_hash(tmp_path):
    original = tmp_path / "ml-generated.rules"
    raw = (RULE + "\n").encode()
    original.write_bytes(raw)
    source_sha = verify_pinned_rule_artifact(
        original, expected_sid=9103999, expected_text_sha256=RULE_SHA,
    )
    assert source_sha == hashlib.sha256(raw).hexdigest()
    assert source_sha != RULE_SHA


@pytest.mark.parametrize(
    "raw",
    [
        RULE.encode(),                         # Missing required terminal newline
        (RULE + "\n\n").encode(),              # More than one newline
        (RULE + "\r\n").encode(),             # CRLF not canonical LF
        (RULE + "\nmalicious").encode(),      # Second unreviewed line
    ],
)
def test_rejects_any_noncanonical_original_rule_bytes(tmp_path, raw):
    path = tmp_path / "rule.rules"
    path.write_bytes(raw)
    with pytest.raises(ReplayGateError, match="LF"):
        verify_pinned_rule_artifact(
            path, expected_sid=9103999, expected_text_sha256=RULE_SHA,
        )


def test_rejects_incorrect_rule_sha_or_sid(tmp_path):
    path = tmp_path / "rule.rules"
    path.write_text(RULE + "\n", encoding="utf-8")
    with pytest.raises(ReplayGateError, match="SHA256"):
        verify_pinned_rule_artifact(
            path, expected_sid=9103999, expected_text_sha256="0" * 64,
        )
    with pytest.raises(ReplayGateError, match="alert-only"):
        verify_pinned_rule_artifact(
            path, expected_sid=9103998, expected_text_sha256=RULE_SHA,
        )


def test_rejects_symlinked_original_rule(tmp_path):
    original = tmp_path / "original.rules"
    original.write_text(RULE + "\n", encoding="utf-8")
    link = tmp_path / "linked.rules"
    try:
        link.symlink_to(original)
    except (NotImplementedError, OSError):
        pytest.skip("Symlink privileges unavailable")
    with pytest.raises(ReplayGateError, match="unsafe"):
        verify_pinned_rule_artifact(
            link, expected_sid=9103999, expected_text_sha256=RULE_SHA,
        )
