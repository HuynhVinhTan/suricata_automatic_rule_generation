"""Fail-closed, review-only lifecycle for isolated Suricata rule candidates."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path


class LifecycleError(ValueError):
    pass


_SHA = re.compile(r"^[0-9a-f]{64}$")
_RUN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_STATES = {
    "PROPOSED", "VALIDATING", "REJECTED", "VALIDATED_FOR_REVIEW",
    "AWAITING_APPROVAL", "APPROVED_FOR_ISOLATED_LAB", "STAGED_IN_ISOLATED_LAB",
    "ACTIVE_IN_ISOLATED_LAB", "ROLLED_BACK", "FAILED",
}
_TRANSITIONS = {
    "PROPOSED": {"VALIDATING", "REJECTED", "FAILED"},
    "VALIDATING": {"VALIDATED_FOR_REVIEW", "REJECTED", "FAILED"},
    "VALIDATED_FOR_REVIEW": {"AWAITING_APPROVAL", "REJECTED", "FAILED"},
    "AWAITING_APPROVAL": {"APPROVED_FOR_ISOLATED_LAB", "REJECTED", "FAILED"},
    "APPROVED_FOR_ISOLATED_LAB": {"STAGED_IN_ISOLATED_LAB", "ROLLED_BACK", "FAILED"},
    "STAGED_IN_ISOLATED_LAB": {"ACTIVE_IN_ISOLATED_LAB", "ROLLED_BACK", "FAILED"},
    "ACTIVE_IN_ISOLATED_LAB": {"ROLLED_BACK", "FAILED"},
    "REJECTED": set(), "ROLLED_BACK": set(), "FAILED": set(),
}


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class RuleLifecycle:
    def __init__(self, audit_path: Path):
        self.audit_path = Path(audit_path)

    def _audit(self, event: str, candidate: dict, **details):
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        record = {"event": event, "candidate_id": candidate.get("candidate_id"), **details}
        with self.audit_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, sort_keys=True) + "\n")

    def create_candidate(self, candidate: dict) -> dict:
        required = ("run_id", "pcap_sha256", "model_sha256", "calibration_sha256", "sid", "rule", "rule_sha256")
        if any(key not in candidate for key in required):
            raise LifecycleError("Missing candidate provenance")
        if not _RUN.fullmatch(candidate["run_id"]):
            raise LifecycleError("Invalid run_id")
        if any(not _SHA.fullmatch(candidate[key]) for key in ("pcap_sha256", "model_sha256", "calibration_sha256", "rule_sha256")):
            raise LifecycleError("Invalid provenance hash")
        if type(candidate["sid"]) is not int or not 1 <= candidate["sid"] <= 4294967295:
            raise LifecycleError("Invalid SID")
        if candidate["rule_sha256"] != _sha(candidate["rule"]):
            raise LifecycleError("Rule hash mismatch")
        if any(candidate.get(key) is not False for key in ("approved", "deployable", "deployed")):
            raise LifecycleError("Candidate safety flags must be false")
        result = dict(candidate)
        result.update({"candidate_id": _sha(f"{candidate['run_id']}:{candidate['sid']}:{candidate['rule_sha256']}"), "state": "PROPOSED"})
        self._audit("candidate_created", result, state=result["state"])
        return result

    def transition(self, candidate: dict, state: str) -> dict:
        current = candidate.get("state")
        if state not in _STATES or state not in _TRANSITIONS.get(current, set()):
            raise LifecycleError(f"Invalid lifecycle transition: {current}->{state}")
        candidate["state"] = state
        self._audit("state_transition", candidate, from_state=current, to_state=state)
        return candidate

    def approve(self, candidate: dict, *, approver: str, approved_at: str) -> dict:
        if candidate.get("state") != "AWAITING_APPROVAL":
            raise LifecycleError("Candidate is not awaiting approval")
        if not isinstance(approver, str) or not approver.strip():
            raise LifecycleError("Approver is required")
        try:
            datetime.fromisoformat(approved_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise LifecycleError("Invalid approval timestamp") from exc
        if candidate.get("approved") is not False or candidate.get("deployable") is not False or candidate.get("deployed") is not False:
            raise LifecycleError("Approval safety flags must remain false")
        candidate["approval"] = {"approver": approver, "approved_at": approved_at, "candidate_id": candidate["candidate_id"], "rule_sha256": candidate["rule_sha256"]}
        self.transition(candidate, "APPROVED_FOR_ISOLATED_LAB")
        return candidate

    def stage(self, candidate: dict, lab_rules_dir: Path, *, activate: bool = False) -> dict:
        if candidate.get("state") != "APPROVED_FOR_ISOLATED_LAB":
            raise LifecycleError("Explicit approval is required before staging")
        if candidate.get("approval", {}).get("rule_sha256") != candidate.get("rule_sha256"):
            raise LifecycleError("Approval rule hash mismatch")
        if candidate.get("rule_sha256") != _sha(candidate.get("rule", "")):
            raise LifecycleError("Rule hash mismatch")
        target = Path(lab_rules_dir)
        if target.is_symlink() or ".." in target.parts:
            raise LifecycleError("Unsafe isolated-lab path")
        self._audit("stage_requested", candidate, path=str(target), activate=activate)
        if activate:
            raise LifecycleError("Active isolated-lab installation requires separate owner authorization")
        return {"status": "dry_run", "candidate_id": candidate["candidate_id"], "path": str(target)}

    def rollback(self, candidate: dict) -> dict:
        self.transition(candidate, "ROLLED_BACK")
        self._audit("rollback", candidate)
        return candidate
