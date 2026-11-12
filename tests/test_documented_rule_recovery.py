"""Documented-frozen rule recovery is explicit and fail-closed."""

import hashlib
import subprocess

import pytest

from netids.documented_rule_recovery import (
    RecoveryError,
    recover_documented_frozen_rule,
)
from netids.trusted_replay import (
    DOCUMENTED_EVIDENCE_GIT_BLOB_SHA,
    DOCUMENTED_EVIDENCE_PATH,
    DOCUMENTED_EVIDENCE_SHA,
    validate_documented_rule_provenance,
)


RULE = (
    'alert tcp 192.168.10.10 any -> 192.168.10.20 any '
    '(msg:"ML REVIEW - repeated TCP RST responses"; flow:stateless; '
    'flags:R+; threshold:type threshold,track by_dst,count 3,seconds 60; '
    'classtype:attempted-recon; sid:9103003; rev:1;)'
)


def _repo(tmp_path, evidence_text=RULE):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    path = tmp_path / "evidence.md"
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        stream.write(
            "# frozen\n\n```text\n" + evidence_text + "\n"
            "rule_sha256=" + hashlib.sha256(evidence_text.encode()).hexdigest()
            + "\n```\n"
        )
    subprocess.run(["git", "add", "evidence.md"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "-c", "user.name=test", "-c", "user.email=test@example.invalid",
         "commit", "-qm", "freeze"], cwd=tmp_path, check=True,
    )
    blob = subprocess.check_output(
        ["git", "hash-object", "evidence.md"], cwd=tmp_path, text=True,
    ).strip()
    return path, blob


def test_recovery_extracts_only_pinned_git_evidence_and_marks_missing_history(tmp_path):
    path, blob = _repo(tmp_path)

    recovered = recover_documented_frozen_rule(
        repo_root=tmp_path,
        evidence_path=path,
        evidence_git_blob_sha=blob,
        expected_rule_sha256=hashlib.sha256(RULE.encode()).hexdigest(),
    )

    assert recovered["rule_text"] == RULE
    assert recovered["rule_file_bytes"] == RULE.encode() + b"\n"
    assert recovered["provenance"] == {
        "evidence_class": "documented_frozen_rule_recovery",
        "historical_generated_metadata": "unavailable_not_recovered",
        "source_document_git_blob_sha256": blob,
        "source_document_path": "evidence.md",
        "source_document_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def test_recovery_rejects_changed_worktree_even_when_rule_text_matches(tmp_path):
    path, blob = _repo(tmp_path)
    path.write_text(path.read_text(encoding="utf-8") + "tampered\n", encoding="utf-8")

    with pytest.raises(RecoveryError, match="source document"):
        recover_documented_frozen_rule(
            repo_root=tmp_path,
            evidence_path=path,
            evidence_git_blob_sha=blob,
            expected_rule_sha256=hashlib.sha256(RULE.encode()).hexdigest(),
        )


def test_recovery_rejects_rejected_rst_artifact_text(tmp_path):
    rejected = RULE.replace("flags:R+", "flags:R").replace("count 3", "count 2")
    path, blob = _repo(tmp_path, rejected)

    with pytest.raises(RecoveryError, match="rule SHA256"):
        recover_documented_frozen_rule(
            repo_root=tmp_path,
            evidence_path=path,
            evidence_git_blob_sha=blob,
            expected_rule_sha256=hashlib.sha256(RULE.encode()).hexdigest(),
        )


def test_replay_gate_rejects_unlabelled_or_modified_recovery_provenance():
    with pytest.raises(ValueError, match="documented-source"):
        validate_documented_rule_provenance({})
    validate_documented_rule_provenance({
        "evidence_class": "documented_frozen_rule_recovery",
        "historical_generated_metadata": "unavailable_not_recovered",
        "source_document_git_blob_sha256": DOCUMENTED_EVIDENCE_GIT_BLOB_SHA,
        "source_document_path": DOCUMENTED_EVIDENCE_PATH,
        "source_document_sha256": DOCUMENTED_EVIDENCE_SHA,
    })
