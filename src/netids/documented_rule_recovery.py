"""Recover a frozen review rule from an immutable, pinned Git evidence source.

This is not historical generator-artifact recovery.  It deliberately emits a
separate provenance class when the original RST metadata is unavailable.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path


class RecoveryError(ValueError):
    """Pinned documented-source recovery failed closed."""


_RULE_LINE = re.compile(r"^alert tcp .*\bsid:(?P<sid>\d+);.*$")
_RULE_HASH = re.compile(r"^rule_sha256=(?P<sha>[0-9a-f]{64})$")


def _git_blob(repo_root: Path, path: Path, expected: str) -> bytes:
    if not re.fullmatch(r"[0-9a-f]{40}", expected):
        raise RecoveryError("Invalid pinned evidence Git blob SHA")
    try:
        relative_path = path.resolve().relative_to(repo_root.resolve()).as_posix()
        actual = subprocess.check_output(
            ["git", "hash-object", f"--path={relative_path}", "--", str(path)],
            cwd=repo_root,
            stderr=subprocess.DEVNULL,
        ).decode("ascii").strip()
        committed = subprocess.check_output(
            ["git", "cat-file", "blob", expected],
            cwd=repo_root,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RecoveryError("Pinned Git source document cannot be verified") from exc
    # ``--path`` applies Git's configured text normalization.  This keeps the
    # pinned blob check stable on Windows checkouts with core.autocrlf=true
    # while still rejecting any semantic source-document change.
    if actual != expected:
        raise RecoveryError("Pinned source document differs from committed source document")
    return committed


def recover_documented_frozen_rule(
    *,
    repo_root: Path,
    evidence_path: Path,
    evidence_git_blob_sha: str,
    expected_rule_sha256: str,
    expected_sid: int = 9103003,
) -> dict:
    """Extract and verify the exact documented rule without inventing history."""
    root = Path(repo_root).resolve()
    path = Path(evidence_path)
    if path.is_symlink() or not path.is_file():
        raise RecoveryError("Pinned source document is missing or unsafe")
    try:
        relative = path.resolve().relative_to(root)
    except ValueError as exc:
        raise RecoveryError("Source document is outside the repository") from exc
    if not re.fullmatch(r"[0-9a-f]{64}", expected_rule_sha256):
        raise RecoveryError("Invalid expected rule SHA256")

    document = _git_blob(root, path, evidence_git_blob_sha)
    try:
        text = document.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RecoveryError("Source document is not valid UTF-8") from exc
    rule_lines = [line for line in text.splitlines() if _RULE_LINE.fullmatch(line)]
    hash_lines = [_RULE_HASH.fullmatch(line) for line in text.splitlines()]
    if len(rule_lines) != 1 or len([match for match in hash_lines if match]) != 1:
        raise RecoveryError("Source document must contain exactly one rule and hash")
    rule_text = rule_lines[0]
    declared_hash = next(match.group("sha") for match in hash_lines if match)
    actual_hash = hashlib.sha256(rule_text.encode("utf-8")).hexdigest()
    if declared_hash != expected_rule_sha256 or actual_hash != expected_rule_sha256:
        raise RecoveryError("Documented rule SHA256 does not match the pinned rule SHA256")
    sid_match = re.search(r"\bsid:(\d+);", rule_text)
    if sid_match is None or int(sid_match.group(1)) != expected_sid:
        raise RecoveryError("Documented rule SID does not match the pinned SID")
    if "flags:R+" not in rule_text or "threshold:type threshold,track by_dst,count 3,seconds 60" not in rule_text:
        raise RecoveryError("Documented rule is not the accepted RST rule")

    return {
        "rule_text": rule_text,
        "rule_file_bytes": rule_text.encode("utf-8") + b"\n",
        "rule_sha256": actual_hash,
        "rule_file_sha256": hashlib.sha256(rule_text.encode("utf-8") + b"\n").hexdigest(),
        "provenance": {
            "evidence_class": "documented_frozen_rule_recovery",
            "historical_generated_metadata": "unavailable_not_recovered",
            "source_document_git_blob_sha256": evidence_git_blob_sha,
            "source_document_path": relative.as_posix(),
            "source_document_sha256": hashlib.sha256(document).hexdigest(),
        },
    }
