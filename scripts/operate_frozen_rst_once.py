#!/usr/bin/env python3
"""Run one owner-authorized SID9103005 isolated activation and rollback."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import socket
from datetime import datetime, timezone
from pathlib import Path

from netids.g5_frozen_candidate import (
    FROZEN_OWNER_DOMAIN,
    FROZEN_REPLAY_DOMAIN,
    FROZEN_RUNTIME_DOMAIN,
    FROZEN_RUNTIME_SCHEMA,
    FrozenCandidateError,
    verify_frozen_candidate,
    verify_frozen_owner_authorization,
    verify_frozen_replay_attestation,
    verify_frozen_runtime_result,
)
from netids.isolated_suricata_runtime import (
    IsolatedSuricataRuntime, VM1_HOST, is_verified_vm1_host,
    validate_attempt_namespace,
)
from netids.lifecycle_ed25519 import private_key_matches_public, sha256_file, sign_record
from netids.latency import LatencyTrace
from netids.privilege_separation import require_root_operator_if_supported
from netids.rule_lifecycle import RuleLifecycle
from scripts.operate_isolated_once import OperationError, _digest, _read_json, _require_candidate_baseline, production_snapshot


SID = 9103005
RUNTIME_ID = "suricata-vm1:isolated-lifecycle-9103005:lo"


def _write_exclusive(path, value):
    if path.exists() or path.is_symlink():
        raise OperationError("output exists; refusing overwrite")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def _probe_paths(specs, probe_plan):
    if not isinstance(specs, (list, tuple)) or len(specs) != len(probe_plan):
        raise OperationError("exactly six signed cohort probes are required")
    expected = {probe["case"]: probe for probe in probe_plan}
    paths = {}
    for spec in specs:
        if "=" not in str(spec):
            raise OperationError("probe must be CASE=ABSOLUTE_PATH")
        case, raw_path = str(spec).split("=", 1)
        if case not in expected or case in paths or not raw_path:
            raise OperationError("probe case substitution or duplicate")
        path = Path(raw_path)
        if path.is_symlink() or not path.is_file():
            raise OperationError(f"probe path is not a regular file: {path}")
        if sha256_file(path) != expected[case]["pcap_sha256"]:
            raise OperationError(f"probe hash mismatch for {case}")
        paths[case] = path
    if set(paths) != set(expected):
        raise OperationError("probes do not cover the exact signed cohort")
    return [dict(probe, path=paths[probe["case"]]) for probe in probe_plan]


def _require_runtime_keypair(runtime_private_pem, runtime_private_password, runtime_public_pem):
    if not private_key_matches_public(runtime_private_pem, runtime_private_password, runtime_public_pem):
        raise OperationError("runtime private/public key mismatch")


def _production_state(before, after):
    if not isinstance(before, dict) or not isinstance(after, dict):
        return "not_verified"
    return "unchanged" if before == after else "changed"


def execute_frozen_once(
    *, candidate_file, replay_file, owner_file, replay_public_file, owner_public_file,
    runtime_public_file,
    production_yaml, production_rules, isolated_yaml, isolated_root,
    attempt_id, probe_specs, audit_path, failure_path,
    runtime_private_pem, runtime_private_password,
):
    if not is_verified_vm1_host():
        raise OperationError("owner authorization is only for verified VM1")
    try:
        require_root_operator_if_supported()
    except RuntimeError as exc:
        raise OperationError(str(exc)) from exc
    try:
        attempt_evidence_root, _ = validate_attempt_namespace(isolated_root, attempt_id)
    except ValueError as exc:
        raise OperationError(str(exc)) from exc
    if not Path(failure_path).resolve().is_relative_to(attempt_evidence_root):
        raise OperationError("attempt evidence output must remain inside its attempt namespace")
    candidate = _read_json(candidate_file)
    replay = _read_json(replay_file)
    owner = _read_json(owner_file)
    trace_run_id = candidate.get("run_id") if isinstance(candidate.get("run_id"), str) else f"invalid-g5-{SID}"
    latency = LatencyTrace(
        run_id=trace_run_id,
        host=socket.gethostname(),
        clock_sync={"status": "same_process_monotonic", "offset_ms": 0.0},
    )
    for name, component in (
        ("capture", "capture"),
        ("capture_sealing", "capture"),
        ("handoff_transport", "transport"),
        ("handoff_receipt", "transport"),
        ("worker_queue", "worker"),
        ("worker_processing", "worker"),
        ("feature_extraction", "ai"),
        ("model_inference", "ai"),
        ("hybrid_evaluation", "hybrid"),
        ("candidate_generation", "hybrid"),
        ("owner_approval_wait", "human"),
    ):
        latency.record(name, status="not_measured", component=component)
    replay_public = Path(replay_public_file).read_bytes()
    owner_public = Path(owner_public_file).read_bytes()
    runtime_public = Path(runtime_public_file).read_bytes()
    try:
        with latency.stage("candidate_validation", component="hybrid"):
            verify_frozen_candidate(candidate, candidate.get("baseline_comparison"))
    except FrozenCandidateError as exc:
        raise OperationError(str(exc)) from exc
    with latency.stage("replay_attestation", component="human"):
        if not verify_frozen_replay_attestation(candidate, replay, replay_public):
            raise OperationError("untrusted or mismatched frozen replay attestation")
    with latency.stage("owner_authorization_verification", component="human"):
        if not verify_frozen_owner_authorization(candidate, replay, owner, replay_public, owner_public, runtime_public):
            raise OperationError("untrusted or mismatched frozen owner authorization")
    if (
        owner.get("runtime_id") != RUNTIME_ID
        or owner.get("target_vm") != VM1_HOST
        or owner.get("interface") != "lo"
        or owner.get("isolated_root") != str(Path(isolated_root).resolve())
    ):
        raise OperationError("frozen owner authorization scope mismatch")
    if Path(audit_path).resolve() != Path(isolated_root).resolve() / "audit" / "owner-once.jsonl":
        raise OperationError("audit path must be the candidate-specific persistent one-shot ledger")
    with latency.stage("production_safety_snapshot_before", component="runtime"):
        before = production_snapshot(production_yaml, production_rules, forbidden_sid=SID)
    _require_candidate_baseline(candidate, before)
    with latency.stage("probe_hash_verification", component="runtime"):
        probe_plan = _probe_paths(probe_specs, replay["probe_plan"])
        _require_runtime_keypair(runtime_private_pem, runtime_private_password, runtime_public)
    lifecycle = None
    runtime = None
    started = datetime.now(timezone.utc)
    started_monotonic = __import__("time").monotonic()
    deadline = started_monotonic + 300
    after = None
    operation_error = None
    cleanup_verified = False
    cleanup_process_stopped = False
    cleanup_artifacts_removed = False
    signed = None
    try:
        lifecycle = RuleLifecycle(
            audit_path, isolated_root=isolated_root,
            replay_verification_key=replay_public, owner_verification_key=owner_public,
            attestation_mode="ed25519", replay_domain=FROZEN_REPLAY_DOMAIN,
            owner_domain=FROZEN_OWNER_DOMAIN,
        )
        proposed = lifecycle.create_candidate(candidate)
        lifecycle.transition(proposed, "VALIDATING")
        lifecycle.record_validation(proposed, replay)
        lifecycle.transition(proposed, "AWAITING_APPROVAL")
        lifecycle.approve(proposed, owner)
        runtime = IsolatedSuricataRuntime(
            config=isolated_yaml,
            attack_pcap=next(probe["path"] for probe in probe_plan if probe["label"] == "ATTACK"),
            attack_sha256=next(probe["pcap_sha256"] for probe in probe_plan if probe["label"] == "ATTACK"),
            normal_pcap=next(probe["path"] for probe in probe_plan if probe["label"] == "NORMAL"),
            normal_sha256=next(probe["pcap_sha256"] for probe in probe_plan if probe["label"] == "NORMAL"),
            probe_plan=probe_plan, deadline_monotonic=deadline,
            candidate_sid=SID, candidate_rule_sha256=candidate["rule_sha256"],
            root=isolated_root, attempt_id=attempt_id, latency_trace=latency,
        )
        staged = lifecycle.stage(proposed, Path(isolated_root) / "rules", activate=True, runtime=runtime)
        if staged.get("status") != "active_in_isolated_lab":
            raise OperationError("candidate did not reach verified active isolated state")
        lifecycle.rollback(proposed, runtime=runtime)
        if proposed.get("state") != "ROLLED_BACK":
            raise OperationError("mandatory rollback was not verified")
        elapsed_seconds = round(__import__("time").monotonic() - started_monotonic, 3)
        if elapsed_seconds > 300:
            raise OperationError("owner-authorized operation exceeded 300 seconds")
        with latency.stage("production_safety_snapshot_after", component="runtime"):
            after = production_snapshot(production_yaml, production_rules, forbidden_sid=SID)
        if before != after:
            raise OperationError("production before/after state changed")
        result = {
            "schema_version": FROZEN_RUNTIME_SCHEMA,
            "candidate_id": candidate["candidate_id"],
            "sid": SID,
            "rule_file_sha256": candidate["rule_file_sha256"],
            "replay_evidence_sha256": _digest(replay),
            "owner_authorization_sha256": _digest(owner),
            "elapsed_seconds": elapsed_seconds,
            "max_runtime_seconds": 300,
            "deadline_enforced": True,
            "candidate_loaded": True,
            "attack_replay_passed": True,
            "normal_replay_passed": True,
            "negative_control_passed": True,
            "rollback_verified": True,
            "post_rollback_verified": True,
            "child_process_cleanup_verified": runtime.process is not None and runtime.process.poll() is not None,
            "production_unchanged": True,
            "probe_results": runtime.probe_results,
            "production_before": before,
            "production_after": after,
            "lifecycle_audit_records": lifecycle.verify_audit(),
            "outcome": "VERIFIED_ISOLATED_ACTIVATION_AND_ROLLBACK",
            "approved": False,
            "deployed": False,
            "latency_trace_binding": "signed_runtime_result_field",
            "latency_trace": latency.as_dict(),
        }
        if not private_key_matches_public(runtime_private_pem, runtime_private_password, runtime_public):
            raise OperationError("runtime private key does not match the trusted runtime public key")
        signed = sign_record(result, runtime_private_pem, runtime_private_password, domain=FROZEN_RUNTIME_DOMAIN)
        verify_frozen_runtime_result(candidate, replay, signed, runtime_public)
    except Exception as exc:
        operation_error = exc
    finally:
        if runtime is not None:
            try:
                cleanup_verified = runtime.shutdown() is True
                if not cleanup_verified and operation_error is None:
                    operation_error = OperationError("isolated runtime cleanup was not verified")
            except Exception as cleanup_error:
                cleanup_verified = False
                operation_error = operation_error or cleanup_error
            cleanup_process_stopped = runtime.process is None or runtime.process.poll() is not None
            cleanup_artifacts_removed = not any(
                path.exists() for path in (runtime.pidfile, runtime.socket_path, runtime.active_rules)
            )
        else:
            cleanup_process_stopped = True
            cleanup_artifacts_removed = True

    if operation_error is not None:
        if before is not None:
            try:
                after = production_snapshot(production_yaml, production_rules, forbidden_sid=SID)
            except Exception:
                after = None
        production_state = _production_state(before, after)
        audit_records = None
        if lifecycle is not None:
            try:
                audit_records = lifecycle.verify_audit()
            except Exception:
                audit_records = None
        diagnostic_path = getattr(runtime, "diagnostic_path", None) if runtime is not None else None
        diagnostic_sha256 = (
            sha256_file(diagnostic_path) if diagnostic_path is not None and diagnostic_path.is_file() else None
        )
        rollback_verified = bool(
            runtime is not None
            and runtime.rollback_verified
            and runtime.post_rollback_verified
        )
        rollback_status = (
            "verified" if rollback_verified
            else "unverified" if runtime is not None and runtime.rollback_attempted
            else "not_attempted"
        )
        report = {
            "schema_version": "g5_frozen_runtime_failure_v1",
            "candidate_id": candidate.get("candidate_id"),
            "sid": SID,
            "attempt_id": attempt_id,
            "attempt_evidence_root": str(
                getattr(runtime, "attempt_root", attempt_evidence_root)
            ),
            "failure_phase": getattr(runtime, "failure_phase", None) or "operator",
            "failure_reason": str(operation_error),
            "outcome": "FAILED",
            "accepted": False,
            "rollback_status": rollback_status,
            "rollback_verified": rollback_verified,
            "cleanup_status": "verified" if cleanup_verified else "failed" if runtime is not None else "not_attempted",
            "cleanup_verified": cleanup_verified,
            "cleanup_process_stopped": cleanup_process_stopped,
            "cleanup_artifacts_removed": cleanup_artifacts_removed,
            "production_state": production_state,
            "production_unchanged": production_state == "unchanged",
            "production_before": before,
            "production_after": after,
            "replay_evidence_sha256": _digest(replay),
            "owner_authorization_sha256": _digest(owner),
            "lifecycle_audit_records": audit_records,
            "lifecycle_audit_sha256": sha256_file(audit_path) if Path(audit_path).is_file() else None,
            "diagnostic_log_path": str(diagnostic_path) if diagnostic_path is not None else None,
            "diagnostic_log_sha256": diagnostic_sha256,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "latency_trace_binding": "unsigned_failure_record_field",
            "latency_trace": latency.as_dict(),
        }
        _write_exclusive(failure_path, report)
        raise operation_error
    return signed


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    paths = (
        "candidate", "replay", "owner-authorization", "replay-public", "owner-public", "runtime-public",
        "production-yaml", "production-rules", "isolated-yaml", "isolated-root",
        "audit-path", "runtime-private",
        "evidence-output", "failure-output",
    )
    for name in paths:
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--attempt-id", required=True)
    parser.add_argument("--probe", action="append", required=True, help="six CASE=ABSOLUTE_PATH entries from the signed cohort")
    args = parser.parse_args(argv)
    if args.evidence_output.exists() or args.failure_output.exists():
        parser.error("evidence/failure output exists; never overwrite")
    try:
        attempt_evidence_root, _ = validate_attempt_namespace(args.isolated_root, args.attempt_id)
    except ValueError as exc:
        parser.error(str(exc))
    if not args.evidence_output.resolve().is_relative_to(attempt_evidence_root):
        parser.error("evidence output must remain inside its attempt namespace")
    if not args.failure_output.resolve().is_relative_to(attempt_evidence_root):
        parser.error("failure output must remain inside its attempt namespace")
    password = getpass.getpass("Runtime encrypted signing key passphrase: ").encode()
    evidence = execute_frozen_once(
        candidate_file=args.candidate, replay_file=args.replay,
        owner_file=args.owner_authorization, replay_public_file=args.replay_public,
        owner_public_file=args.owner_public, runtime_public_file=args.runtime_public,
        production_yaml=args.production_yaml,
        production_rules=args.production_rules, isolated_yaml=args.isolated_yaml,
        isolated_root=args.isolated_root, attempt_id=args.attempt_id, probe_specs=args.probe,
        audit_path=args.audit_path,
        failure_path=args.failure_output, runtime_private_pem=args.runtime_private.read_bytes(),
        runtime_private_password=password,
    )
    _write_exclusive(args.evidence_output, evidence)
    print(f"Frozen runtime evidence saved: {args.evidence_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
