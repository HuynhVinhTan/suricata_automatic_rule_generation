import copy
import hashlib
import json
from pathlib import Path

import pytest

from netids.rst_candidate_verification import (
    RstCandidateVerificationError,
    build_g5_acceptance_request,
    verify_frozen_rst_candidate,
)


ROOT = Path(__file__).resolve().parents[1]
STAGING = ROOT / ".runtime-staging"
DEV_DIR = STAGING / "g4-rst-dev-20261124T075112Z-9d0b815b"
HOLDOUT_DIR = STAGING / "g4-holdout-20261124T084145Z-fd9f2786"


def _paths():
    return {
        "freeze_path": DEV_DIR / "acceptance-freeze.json",
        "development_evidence_path": DEV_DIR / "development-evidence.json",
        "holdout_report_path": HOLDOUT_DIR / "native-holdout-replay.json",
        "cohort_results_path": HOLDOUT_DIR / "cohort-results.json",
        "cohort_plan_path": HOLDOUT_DIR / "cohort-plan.json",
        "rule_path": DEV_DIR / "ml-generated-rst.rules",
        "metadata_path": DEV_DIR / "ml-generated-rst.metadata.json",
    }


@pytest.mark.skipif(
    not (DEV_DIR / "acceptance-freeze.json").is_file(),
    reason="owner-supplied runtime evidence is not present in this checkout",
)
def test_verifies_owner_supplied_frozen_rst_evidence_without_approval():
    result = verify_frozen_rst_candidate(
        **_paths(),
        expected_source_commit="c3aaa982fcb2d38b71d51ac9ae2af8a41b3e1dad",
        expected_sid=9103005,
        expected_freeze_sha256="74ce643d782d525e83910138b32218bc69e8d97a6908e725f71dbbeab0fd9bd4",
        expected_cohort_sha256="443b42478b3bfbc0d66433fc5e582433426962fe54427278b584a5e5e859efaa",
    )

    assert result["verified"] is True
    assert result["sid"] == 9103005
    assert result["metrics"] == {"TP": 3, "FN": 0, "FP": 0, "TN": 3}
    assert result["approved"] is False
    assert result["deployed"] is False
    assert result["bounded_laboratory_signature"] is True
    assert result["hybrid_equivalent"] is False


@pytest.mark.skipif(
    not (DEV_DIR / "acceptance-freeze.json").is_file(),
    reason="owner-supplied runtime evidence is not present in this checkout",
)
def test_frozen_evidence_tamper_and_holdout_overlap_fail_closed(tmp_path):
    paths = _paths()
    freeze = json.loads(paths["freeze_path"].read_text(encoding="utf-8"))
    freeze["cohort_results_sha256"] = "0" * 64
    tampered = tmp_path / "acceptance-freeze.json"
    tampered.write_text(json.dumps(freeze), encoding="utf-8")

    with pytest.raises(RstCandidateVerificationError, match="freeze SHA256"):
        verify_frozen_rst_candidate(
            **{**paths, "freeze_path": tampered},
            expected_source_commit="c3aaa982fcb2d38b71d51ac9ae2af8a41b3e1dad",
            expected_sid=9103005,
            expected_freeze_sha256="74ce643d782d525e83910138b32218bc69e8d97a6908e725f71dbbeab0fd9bd4",
            expected_cohort_sha256="443b42478b3bfbc0d66433fc5e582433426962fe54427278b584a5e5e859efaa",
        )

    holdout = json.loads(paths["holdout_report_path"].read_text(encoding="utf-8"))
    holdout["cases"][0]["pcap_sha256"] = holdout["cases"][1]["pcap_sha256"]
    tampered_holdout = tmp_path / "native-holdout-replay.json"
    tampered_holdout.write_text(json.dumps(holdout), encoding="utf-8")

    with pytest.raises(RstCandidateVerificationError, match="duplicate holdout"):
        verify_frozen_rst_candidate(
            **{**paths, "holdout_report_path": tampered_holdout},
            expected_source_commit="c3aaa982fcb2d38b71d51ac9ae2af8a41b3e1dad",
            expected_sid=9103005,
            expected_freeze_sha256="74ce643d782d525e83910138b32218bc69e8d97a6908e725f71dbbeab0fd9bd4",
            expected_cohort_sha256="443b42478b3bfbc0d66433fc5e582433426962fe54427278b584a5e5e859efaa",
        )


def test_g5_request_is_review_only_and_candidate_bound():
    verification = {
        "verified": True,
        "sid": 9103005,
        "rule_file_sha256": "1" * 64,
        "freeze_sha256": "2" * 64,
        "cohort_results_sha256": "3" * 64,
        "approved": False,
        "deployed": False,
        "bounded_laboratory_signature": True,
        "hybrid_equivalent": False,
    }

    request = build_g5_acceptance_request(verification)

    assert request["status"] == "awaiting_owner_runtime"
    assert request["operation"] == "isolated_activation_and_rollback"
    assert request["requires_owner_authorization"] is True
    assert request["approved"] is False
    assert request["deployed"] is False
    assert request["rollback_required"] is True
    assert request["sid"] == 9103005


def test_g5_request_rejects_unverified_or_approved_input():
    verification = {
        "verified": False,
        "sid": 9103005,
        "rule_file_sha256": "1" * 64,
        "freeze_sha256": "2" * 64,
        "cohort_results_sha256": "3" * 64,
        "approved": False,
        "deployed": False,
    }
    with pytest.raises(RstCandidateVerificationError, match="verified"):
        build_g5_acceptance_request(verification)

    verification["verified"] = True
    verification["approved"] = True
    with pytest.raises(RstCandidateVerificationError, match="approved"):
        build_g5_acceptance_request(verification)
