"""Fail-closed review-only lifecycle for isolated Suricata rule candidates.

This is an isolated-lab protocol, not a production rule deployment interface.
An authenticated replay record is evidence only if its signing service actually
verified a real Suricata replay. No keys, approvals, or live runtime are bundled.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from netids.lifecycle_attestation import verify_attestation
from netids.lifecycle_ed25519 import verify_record as verify_ed25519_record
from netids.rulegen import REJECTED_SIDS, collect_sids


class LifecycleError(ValueError):
    """An evidence, authorization, or lifecycle invariant failed."""


_SHA = re.compile(r"^[0-9a-f]{64}$")
_NONCE = re.compile(r"^[0-9a-f]{32,64}$")
_RUN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_TRANSITIONS = {
    "PROPOSED": {"VALIDATING", "REJECTED", "FAILED"},
    "VALIDATING": {"VALIDATED_FOR_REVIEW", "REJECTED", "FAILED"},
    "VALIDATED_FOR_REVIEW": {"AWAITING_APPROVAL", "REJECTED", "FAILED"},
    "AWAITING_APPROVAL": {"APPROVED_FOR_ISOLATED_LAB", "REJECTED", "FAILED"},
    "APPROVED_FOR_ISOLATED_LAB": {"STAGED_IN_ISOLATED_LAB", "ROLLED_BACK", "FAILED"},
    "STAGED_IN_ISOLATED_LAB": {"ACTIVE_IN_ISOLATED_LAB", "ROLLED_BACK", "FAILED"},
    "ACTIVE_IN_ISOLATED_LAB": {"ROLLED_BACK", "FAILED"},
    "REJECTED": set(),
    "ROLLED_BACK": set(),
    "FAILED": set(),
}
_INTERNAL = frozenset({
    "VALIDATED_FOR_REVIEW", "APPROVED_FOR_ISOLATED_LAB",
    "STAGED_IN_ISOLATED_LAB", "ACTIVE_IN_ISOLATED_LAB", "ROLLED_BACK",
})


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical(value: dict) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _when(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.utcoffset() is None:
            raise ValueError("Naive timestamp")
        return parsed.astimezone(timezone.utc)
    except (AttributeError, TypeError, ValueError) as exc:
        raise LifecycleError("Invalid timezone-aware authorization timestamp") from exc


class RuleLifecycle:
    def __init__(
        self,
        audit_path: Path,
        *,
        isolated_root: Path | None = None,
        existing_sids=(),
        replay_verification_key: bytes | None = None,
        owner_verification_key: bytes | None = None,
        attestation_mode: str = "ed25519",
    ):
        self.audit_path = Path(audit_path)
        raw_root = Path(isolated_root or self.audit_path.parent / "isolated-lab")
        if raw_root.is_symlink():
            raise LifecycleError("Isolated root must not be a symlink")
        self.isolated_root = raw_root.resolve()
        root_name = self.isolated_root.name.lower()
        if not ("isolated" in root_name or root_name == "lab"):
            raise LifecycleError("Explicit isolated-lab directory is required")
        normalized_root = str(self.isolated_root).replace("\\", "/").lower()
        forbidden = (
            "/etc/suricata", "/var/lib/suricata", "/var/log/suricata",
            "/usr/share/suricata", "/usr/local/etc/suricata",
        )
        if (
            self.isolated_root == Path(self.isolated_root.anchor)
            or any(marker in normalized_root for marker in forbidden)
        ):
            raise LifecycleError("Isolated root overlaps protected Suricata paths")
        self.isolated_root.mkdir(parents=True, exist_ok=True)
        self.existing_sids = set(existing_sids)
        if attestation_mode not in ("ed25519", "legacy-hmac"):
            raise LifecycleError("Unknown attestation verification mode")
        self.attestation_mode = attestation_mode
        self.replay_verification_key = replay_verification_key
        self.owner_verification_key = owner_verification_key
        if (
            isinstance(replay_verification_key, bytes)
            and replay_verification_key == owner_verification_key
        ):
            raise LifecycleError("Replay and owner keys must be independent")

    def _audit_records(self) -> list[dict]:
        if not self.audit_path.exists():
            return []
        previous = "0" * 64
        records = []
        try:
            with self.audit_path.open("r", encoding="utf-8") as source:
                for sequence, line in enumerate(source, 1):
                    record = json.loads(line)
                    if not isinstance(record, dict):
                        raise LifecycleError("Corrupt audit record")
                    digest = record.get("record_hash")
                    unsigned = {key: value for key, value in record.items() if key != "record_hash"}
                    expected = _sha(_canonical(unsigned) + previous)
                    if (
                        record.get("sequence") != sequence
                        or record.get("previous_record_hash") != previous
                        or not isinstance(digest, str)
                        or digest != expected
                    ):
                        raise LifecycleError("Audit chain verification failed")
                    records.append(record)
                    previous = digest
        except (OSError, UnicodeError, ValueError, TypeError) as exc:
            raise LifecycleError("Audit chain unreadable or invalid") from exc
        return records

    def _audit(self, event: str, candidate: dict, **details) -> None:
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self.audit_path.with_name(self.audit_path.name + ".lock")
        try:
            handle = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as exc:
            raise LifecycleError("Concurrent or interrupted audit writer") from exc
        try:
            os.close(handle)
            records = self._audit_records()
            if event == "owner_approval_accepted":
                nonce = details["authorization_nonce"]
                if any(
                    row.get("event") == "owner_approval_accepted"
                    and row.get("authorization_nonce") == nonce
                    for row in records
                ):
                    raise LifecycleError("Authorization replay rejected")
            previous = records[-1]["record_hash"] if records else "0" * 64
            record = {
                "sequence": len(records) + 1,
                "previous_record_hash": previous,
                "event": event,
                "candidate_id": candidate.get("candidate_id"),
                **details,
            }
            record["record_hash"] = _sha(_canonical(record) + previous)
            with self.audit_path.open("a", encoding="utf-8") as target:
                target.write(_canonical(record) + "\n")
                target.flush()
                os.fsync(target.fileno())
        finally:
            lock_path.unlink(missing_ok=True)

    def _verified(self, record: dict, key: bytes | None, domain: str) -> bool:
        if self.attestation_mode == "ed25519":
            return verify_ed25519_record(record, key, domain=domain) if key else False
        return verify_attestation(record, key, domain=domain)

    def verify_audit(self) -> int:
        """Verify every on-disk record before reporting how many exist."""
        return len(self._audit_records())

    def _guard(self, candidate: dict) -> None:
        if not isinstance(candidate, dict):
            raise LifecycleError("Candidate is not an object")
        for key in ("run_id", "pcap_sha256", "model_sha256", "calibration_sha256", "rule_sha256"):
            value = candidate.get(key)
            if not isinstance(value, str) or not (
                _RUN.fullmatch(value) if key == "run_id" else _SHA.fullmatch(value)
            ):
                raise LifecycleError("Candidate provenance malformed")
        sid = candidate.get("sid")
        if type(sid) is not int or not 1 <= sid <= 4294967295:
            raise LifecycleError("Invalid SID")
        if sid in REJECTED_SIDS or sid in self.existing_sids:
            raise LifecycleError("Rejected or conflicting SID")
        rule = candidate.get("rule")
        if (
            not isinstance(rule, str)
            or "\n" in rule
            or "\r" in rule
            or collect_sids([rule]) != {sid}
            or _sha(rule) != candidate["rule_sha256"]
        ):
            raise LifecycleError("Rule text or hash mismatch")
        if any(candidate.get(key) is not False for key in ("approved", "deployable", "deployed")):
            raise LifecycleError("Candidate safety flags must be false")
        if candidate.get("candidate_record_schema") == "candidate_record_v1":
            identity = {
                key: candidate.get(key)
                for key in (
                    "run_id", "sid", "rule_sha256", "pcap_sha256",
                    "model_sha256", "calibration_sha256",
                    "decision_manifest_sha256",
                )
            }
            expected_id = hashlib.sha256(
                json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
        else:
            expected_id = _sha(f"{candidate['run_id']}:{sid}:{candidate['rule_sha256']}")
        if candidate.get("candidate_id") != expected_id:
            raise LifecycleError("Candidate identity mismatch")

    def create_candidate(self, candidate: dict) -> dict:
        if not isinstance(candidate, dict):
            raise LifecycleError("Candidate is not an object")
        required = (
            "run_id", "pcap_sha256", "model_sha256", "calibration_sha256",
            "sid", "rule", "rule_sha256",
        )
        if any(key not in candidate for key in required):
            raise LifecycleError("Missing candidate provenance")
        result = dict(candidate)
        sid = result.get("sid")
        if type(sid) is not int:
            raise LifecycleError("Invalid SID")
        if "candidate_id" not in result:
            result["candidate_id"] = _sha(f"{result['run_id']}:{sid}:{result['rule_sha256']}")
        result["state"] = "PROPOSED"
        self._guard(result)
        self._audit("candidate_created", result, state="PROPOSED")
        return result

    def _advance(self, candidate: dict, state: str) -> dict:
        self._guard(candidate)
        current = candidate.get("state")
        if state not in _TRANSITIONS.get(current, set()):
            raise LifecycleError(f"Invalid lifecycle transition: {current}->{state}")
        self._audit("state_transition", candidate, from_state=current, to_state=state)
        candidate["state"] = state
        return candidate

    def transition(self, candidate: dict, state: str) -> dict:
        if state in _INTERNAL:
            raise LifecycleError("Sensitive transition requires verified lifecycle operation")
        if state == "AWAITING_APPROVAL":
            evidence = candidate.get("validation")
            if not self._verified(
                evidence, self.replay_verification_key, domain="isolated-replay-v1"
            ):
                raise LifecycleError("Authenticated replay evidence is required")
        return self._advance(candidate, state)

    def record_validation(self, candidate: dict, evidence: dict) -> dict:
        self._guard(candidate)
        if candidate.get("state") != "VALIDATING" or "validation" in candidate:
            raise LifecycleError("Candidate is not eligible for validation")
        required = {
            "candidate_id": "candidate_id", "run_id": "run_id",
            "sid": "sid", "rule_sha256": "rule_sha256",
            "pcap_sha256": "pcap_sha256", "model_sha256": "model_sha256",
            "calibration_sha256": "calibration_sha256",
        }
        if not isinstance(evidence, dict) or any(
            evidence.get(key) != candidate[field] for key, field in required.items()
        ):
            raise LifecycleError("Validation provenance mismatch")
        if (
            not isinstance(evidence.get("experiment_id"), str)
            or not evidence["experiment_id"].strip()
            or not all(
                evidence.get(key) is True
                for key in ("syntax_authenticated", "attack_replay_passed", "normal_replay_passed")
            )
            or type(evidence.get("threshold")) is not int
            or evidence["threshold"] < 1
            or type(evidence.get("normal_false_positive_count")) is not int
            or evidence["normal_false_positive_count"] != 0
        ):
            raise LifecycleError("Invalid isolated replay results")
        if not self._verified(
            evidence, self.replay_verification_key, domain="isolated-replay-v1"
        ):
            raise LifecycleError("Authenticated replay attestation required")
        self._audit("validation_recorded", candidate, attestation_sha256=_sha(_canonical(evidence)))
        candidate["validation"] = dict(evidence)
        return self._advance(candidate, "VALIDATED_FOR_REVIEW")

    def _valid_authorization(self, candidate: dict, authorization: dict, *, operation: str) -> None:
        required = {
            "candidate_id": "candidate_id", "run_id": "run_id",
            "sid": "sid", "rule_sha256": "rule_sha256",
        }
        if not isinstance(authorization, dict) or any(
            authorization.get(key) != candidate[value] for key, value in required.items()
        ):
            raise LifecycleError("Authorization provenance mismatch")
        if (
            authorization.get("environment") != "isolated-lab"
            or authorization.get("operation") not in ("stage", "activate")
            or (operation == "activate" and authorization.get("operation") != "activate")
            or authorization.get("isolated_root") != str(self.isolated_root)
            or not isinstance(authorization.get("approver_identity"), str)
            or not authorization["approver_identity"].strip()
            or not isinstance(authorization.get("nonce"), str)
            or not _NONCE.fullmatch(authorization["nonce"])
        ):
            raise LifecycleError("Invalid owner authorization scope")
        now = datetime.now(timezone.utc)
        approved = _when(authorization.get("approved_at"))
        expires = _when(authorization.get("expires_at"))
        if (
            expires <= approved
            or approved > now + timedelta(minutes=5)
            or expires <= now
            or expires - approved > timedelta(hours=24)
        ):
            raise LifecycleError("Authorization expired, invalid or not yet valid")
        if not self._verified(
            authorization, self.owner_verification_key,
            domain="isolated-owner-approval-v1",
        ):
            raise LifecycleError("Authenticated owner approval required")

    def approve(
        self, candidate: dict, authorization: dict, authorization_verifier=None,
    ) -> dict:
        self._guard(candidate)
        if candidate.get("state") != "AWAITING_APPROVAL":
            raise LifecycleError("Candidate is not awaiting approval")
        if authorization_verifier is not None:
            raise LifecycleError("Caller-provided authorization verifier is forbidden")
        self._valid_authorization(candidate, authorization, operation="stage")
        self._audit(
            "owner_approval_accepted", candidate, authorization_nonce=authorization["nonce"],
            authorization_sha256=_sha(_canonical(authorization)),
        )
        candidate["approval"] = dict(authorization)
        return self._advance(candidate, "APPROVED_FOR_ISOLATED_LAB")

    def _target(self, path: Path) -> Path:
        requested = Path(path)
        if requested.is_symlink():
            raise LifecycleError("Unsafe isolated-lab path")
        resolved = requested.resolve()
        if not resolved.is_relative_to(self.isolated_root):
            raise LifecycleError("Unsafe isolated-lab path")
        return resolved

    @staticmethod
    def _restore_file(destination: Path, old_bytes: bytes | None) -> None:
        if old_bytes is None:
            destination.unlink(missing_ok=True)
            return
        fd, name = tempfile.mkstemp(prefix=".restore-", dir=destination.parent)
        try:
            with os.fdopen(fd, "wb") as target:
                target.write(old_bytes)
                target.flush()
                os.fsync(target.fileno())
            os.replace(name, destination)
        finally:
            Path(name).unlink(missing_ok=True)

    def stage(
        self, candidate: dict, lab_rules_dir: Path, *, activate: bool = False, runtime=None,
    ) -> dict:
        self._guard(candidate)
        if candidate.get("state") != "APPROVED_FOR_ISOLATED_LAB":
            raise LifecycleError("Explicit approval is required before staging")
        self._valid_authorization(
            candidate, candidate.get("approval"), operation="activate" if activate else "stage",
        )
        if not self._verified(
            candidate.get("validation"), self.replay_verification_key,
            domain="isolated-replay-v1",
        ):
            raise LifecycleError("Replay evidence no longer trusted")
        target = self._target(lab_rules_dir)
        self._audit("stage_requested", candidate, path=str(target), activate=activate)
        if not activate:
            return {"status": "dry_run", "candidate_id": candidate["candidate_id"], "path": str(target)}

        required_methods = ("validate", "activate", "verify_active", "rollback", "verify_rollback")
        if runtime is None or not all(callable(getattr(runtime, method, None)) for method in required_methods):
            raise LifecycleError("Trusted isolated Suricata runtime adapter is required")
        if runtime.validate(candidate["rule"]) is not True:
            raise LifecycleError("Isolated runtime syntax validation failed")

        target.mkdir(parents=True, exist_ok=True)
        destination = target / (candidate["candidate_id"] + ".rules")
        if destination.is_symlink() or (destination.exists() and not destination.is_file()):
            raise LifecycleError("Unsafe existing lab rule target")
        previous = destination.read_bytes() if destination.exists() else None
        staged = False
        try:
            fd, name = tempfile.mkstemp(prefix=".stage-", dir=target)
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(candidate["rule"].encode("utf-8"))
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(name, destination)
            finally:
                Path(name).unlink(missing_ok=True)

            staged = True
            candidate["previous_state"] = {
                "path": str(destination),
                "bytes": previous.hex() if previous is not None else None,
            }
            self._advance(candidate, "STAGED_IN_ISOLATED_LAB")
            if runtime.activate(destination, candidate["sid"], candidate["rule_sha256"]) is not True:
                raise LifecycleError("Isolated Suricata activation failed")
            if runtime.verify_active(candidate["sid"], candidate["rule_sha256"]) is not True:
                raise LifecycleError("Isolated Suricata active ruleset not verified")
            self._advance(candidate, "ACTIVE_IN_ISOLATED_LAB")
            return {"status": "active_in_isolated_lab", "path": str(destination)}
        except Exception as exc:
            self._audit("stage_failed", candidate, error=str(exc))
            if staged:
                restored = False
                try:
                    self._restore_file(destination, previous)
                    restored = (
                        runtime.rollback(destination, candidate["sid"], candidate["rule_sha256"]) is True
                        and runtime.verify_rollback(candidate["sid"], candidate["rule_sha256"]) is True
                    )
                except Exception as rollback_exc:
                    self._audit("rollback_failed", candidate, error=str(rollback_exc))
                if restored:
                    if candidate.get("state") == "STAGED_IN_ISOLATED_LAB":
                        self._advance(candidate, "ROLLED_BACK")
                elif candidate.get("state") in ("STAGED_IN_ISOLATED_LAB", "APPROVED_FOR_ISOLATED_LAB"):
                    self._advance(candidate, "FAILED")
            raise

    def rollback(self, candidate: dict, *, runtime=None) -> dict:
        self._guard(candidate)
        if candidate.get("state") not in ("ACTIVE_IN_ISOLATED_LAB", "STAGED_IN_ISOLATED_LAB"):
            raise LifecycleError("Nothing staged to roll back")
        previous = candidate.get("previous_state")
        if not isinstance(previous, dict):
            raise LifecycleError("Missing verified previous state")
        destination = self._target(Path(previous["path"]))
        if destination.is_symlink():
            raise LifecycleError("Unsafe rollback target")
        old_bytes = bytes.fromhex(previous["bytes"]) if previous["bytes"] is not None else None
        if candidate["state"] == "ACTIVE_IN_ISOLATED_LAB":
            if runtime is None or not all(
                callable(getattr(runtime, name, None)) for name in ("rollback", "verify_rollback")
            ):
                raise LifecycleError("Isolated runtime rollback verification required")
        self._restore_file(destination, old_bytes)
        if candidate["state"] == "ACTIVE_IN_ISOLATED_LAB":
            if (
                runtime.rollback(destination, candidate["sid"], candidate["rule_sha256"]) is not True
                or runtime.verify_rollback(candidate["sid"], candidate["rule_sha256"]) is not True
            ):
                self._audit("rollback_failed", candidate, reason="runtime_rollback_unverified")
                self._advance(candidate, "FAILED")
                raise LifecycleError("Runtime rollback could not be verified")
        self._advance(candidate, "ROLLED_BACK")
        self._audit("rollback_verified", candidate, path=str(destination))
        return candidate
