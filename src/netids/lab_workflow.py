"""Single guarded entry point for the local portion of the lab workflow."""

from __future__ import annotations

import json
from pathlib import Path

from netids.latency import LatencyTrace


def run_streaming_lab_workflow(worker, evidence_path: str | Path) -> dict:
    """Run streaming inference and record every unperformed gate explicitly.

    This is intentionally not an auto-promotion path.  Runtime stages remain
    blocked until independently evaluated artifacts, owner authorization and a
    verified isolated Suricata runtime are supplied by the operator.
    """

    destination = Path(evidence_path)
    if destination.exists():
        raise FileExistsError("Workflow evidence already exists")
    trace = LatencyTrace(run_id=worker.run_id)
    with trace.stage("continuous_inference"):
        result = worker.run_once()

    stages = {
        "continuous_ingestion": {
            "status": "ACCEPTED" if result.processed_events or result.rejected_events else "FAILED",
            "processed_events": result.processed_events,
            "rejected_events": result.rejected_events,
            "dropped_events": result.dropped_events,
        },
        "continuous_inference": {
            "status": "ACCEPTED" if result.processed_events else "FAILED",
            "model_contract": "flow_features_v0.1",
        },
        "hybrid_verification": {
            "status": "BLOCKED",
            "reason": "Packet-level RST/port/handshake telemetry is not present in ordinary EVE flow records",
        },
        "candidate_generation": {
            "status": "BLOCKED",
            "reason": "No safe Suricata signature may be derived without complete Hybrid evidence and independent development data",
        },
        "independent_validation": {
            "status": "BLOCKED",
            "reason": "Requires a frozen new candidate and independent Attack/Normal replay cohort",
        },
        "human_review": {
            "status": "BLOCKED",
            "reason": "Owner approval is not available to the local worker",
        },
        "isolated_staging": {
            "status": "BLOCKED",
            "reason": "Requires authorized isolated Suricata workspace",
        },
        "isolated_activation": {
            "status": "BLOCKED",
            "reason": "Requires exact VM/interface authorization and real Suricata reload/SID evidence",
        },
        "rollback": {
            "status": "BLOCKED",
            "reason": "No live isolated activation was performed, so rollback cannot be experimentally verified",
        },
        "production_preservation": {
            "status": "ACCEPTED",
            "reason": "Worker writes only to its configured review output",
        },
    }
    for name in (
        "feature_window_completed", "hybrid_decision", "candidate_generated",
        "review_completed", "independent_validation", "rule_staged",
        "rule_activated", "first_sid_alert", "rollback_verified",
    ):
        if name not in {entry["name"] for entry in trace.stages}:
            trace.record(name, status="not_measured")

    report = {
        "schema_version": "netids_lab_workflow_v1",
        "run_id": worker.run_id,
        "overall_status": "BLOCKED",
        "stages": stages,
        "latency": trace.as_dict(),
        "evidence_policy": "No production deployment; no runtime claims without fresh external evidence",
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    return report
