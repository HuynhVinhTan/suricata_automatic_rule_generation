"""One-command PCAP -> SYN features -> ML/DL -> review pipeline."""

import argparse
import ipaddress
import json
import subprocess
import sys
from pathlib import Path

from netids.app import run as run_inference
from netids.lab_runtime import sha256
import csv
from netids.rulegen import (
    RST_RESPONSE_FAMILY,
    collect_sids,
    build_syn_burst_review_rule,
    generate_rst_rule,
    write_rst_rule_artifacts,
)
from netids.port_diversity import analyze_port_diversity, read_pcap_syn
from netids.hybrid_review import calibrate_hybrid_thresholds, evaluate_hybrid
from netids.hybrid_provenance import load_calibration_provenance
from netids.rst_evidence import analyze_rst_evidence
from netids.tcp_handshake import summarize_tcp_handshake
from netids.latency import LatencyTrace


def _complete_capture_metadata(metadata):
    if not isinstance(metadata, dict):
        return {}
    return {
        key: metadata[key]
        for key in ("packet_records_complete", "snaplen_truncated", "capture_drops")
        if key in metadata
    }


def _hybrid_reference_evidence(private_root, provenance):
    """Build calibration evidence only from validated provenance entries."""
    evidence = []
    for reference in provenance["references"]:
        path = private_root / reference["path"]
        source_ip = reference["source_ipv4"]
        destination_ip = reference["destination_ipv4"]
        rst = analyze_rst_evidence(
            path,
            source_ip=source_ip,
            destination_ip=destination_ip,
            window_seconds=60,
            capture_metadata=reference["capture_metadata"],
        )
        syn_events = [
            event for event in read_pcap_syn(path)
            if event.src_ip == source_ip and event.dst_ip == destination_ip
        ]
        findings = analyze_port_diversity(
            syn_events, window_seconds=60, min_distinct_ports=1
        )
        handshake = summarize_tcp_handshake(
            path, source_ip=source_ip, destination_ip=destination_ip
        )
        finding = findings[0] if findings else None
        evidence.append({
            "capture_integrity": rst["capture_integrity"],
            "initial_syn_packets": handshake["initial_syn_packets"],
            "handshake_success_count": handshake["flows_with_confirmed_handshake"],
            "unique_destination_ports": (
                finding.max_window_distinct_ports if finding else 0
            ),
            "max_rst_count_per_window": rst["max_rst_count_per_window"],
        })
    return evidence


def _candidate_generation_decision(
    *, candidate_gate_passed, normal_test_counts, attack_counts, attach_candidate
):
    """Select a candidate family without converting Hybrid evidence to SYN counts."""
    if not candidate_gate_passed:
        return {
            "family": None,
            "rejection": None,
            "matches_previous_failed_candidate": False,
        }
    if not normal_test_counts:
        rejection = "missing_normal_validation"
    elif not attack_counts:
        rejection = "missing_attack_inference_evidence"
    else:
        rejection = None
    return {
        "family": RST_RESPONSE_FAMILY,
        "rejection": rejection,
        "matches_previous_failed_candidate": False,
    }


def _rst_evidence_sidecars(private_root):
    candidate_dir = private_root / "lab-rule-candidates" / RST_RESPONSE_FAMILY
    return (
        candidate_dir / "development-evidence.json",
        candidate_dir / "normal-validation-rst.json",
    )


def _load_rst_validation_evidence(private_root):
    """Load a signed-by-hash Normal RST validation sidecar, never holdout data."""
    _, validation_path = _rst_evidence_sidecars(private_root)
    if not validation_path.is_file():
        raise ValueError("missing independent RST validation evidence")
    with validation_path.open("r", encoding="utf-8") as stream:
        evidence = json.load(stream)
    if not isinstance(evidence, dict):
        raise ValueError("RST validation evidence must be an object")
    if evidence.get("scope") != "G4_DEVELOPMENT_VALIDATION_ONLY":
        raise ValueError("RST validation evidence has an invalid scope")
    if evidence.get("final_acceptance") is not False:
        raise ValueError("RST validation evidence is not development-only")
    pcap_sha256 = evidence.get("pcap_sha256")
    if not isinstance(pcap_sha256, str) or len(pcap_sha256) != 64 or any(
        character not in "0123456789abcdefABCDEF" for character in pcap_sha256
    ):
        raise ValueError("RST validation PCAP hash is invalid")
    capture = evidence.get("capture_integrity")
    if not isinstance(capture, dict):
        raise ValueError("RST validation capture is incomplete")
    if not _complete_capture_metadata(capture).get("packet_records_complete") is True:
        raise ValueError("RST validation capture is incomplete")
    if capture.get("snaplen_truncated") is not False or capture.get("capture_drops") is not False:
        raise ValueError("RST validation capture is incomplete")
    counts = evidence.get("rst_counts_by_window")
    if not isinstance(counts, list) or not counts or any(type(value) is not int or value < 0 for value in counts):
        raise ValueError("RST validation counts are missing")
    return evidence, counts


def _load_rst_development_evidence(private_root):
    development_path, _ = _rst_evidence_sidecars(private_root)
    if not development_path.is_file():
        raise ValueError("missing verified RST development evidence")
    with development_path.open("r", encoding="utf-8") as stream:
        evidence = json.load(stream)
    if not isinstance(evidence, dict) or evidence.get("scope") != "G4_DEVELOPMENT_ONLY":
        raise ValueError("RST development evidence has an invalid scope")
    if evidence.get("native_replay_tested") is not False or evidence.get("independent_final_acceptance") is not False:
        raise ValueError("RST development evidence is not frozen before holdout")
    return evidence


def run(pcap, expected_sha, src, dst, private_root, output_dir, capture_metadata=None):
    src = str(ipaddress.IPv4Address(src))
    dst = str(ipaddress.IPv4Address(dst))

    if src == dst:
        raise ValueError("Source and destination must differ")

    if output_dir.exists():
        raise FileExistsError("Pipeline output already exists")

    if not output_dir.resolve().is_relative_to(
        private_root.resolve()
    ):
        raise ValueError("Output must be inside private root")

    if sha256(pcap) != expected_sha.lower():
        raise ValueError("Input PCAP SHA256 mismatch")

    extractor = (
        Path(__file__).resolve().parents[2]
        / "scripts"
        / "extract_syn_windows.py"
    )

    if not extractor.is_file():
        raise FileNotFoundError(
            "SYN extractor missing from application package"
        )

    output_dir.mkdir(parents=True, exist_ok=False)
    latency = LatencyTrace(run_id=output_dir.name)

    features = output_dir / "syn_windows.csv"
    predictions = output_dir / "predictions.json"
    review_path = output_dir / "review.json"

    print("=== STEP 1: PCAP TO SYN FEATURES ===", flush=True)

    with latency.stage("feature_extraction"):
        subprocess.run(
            [
                sys.executable,
                str(extractor),
                "--pcap", str(pcap),
                "--expected-sha256", expected_sha.lower(),
                "--src", src,
                "--dst", dst,
                "--label", "UNLABELED",
                "--window-seconds", "10",
                "--out", str(features),
            ],
            check=True,
        )

    print("=== STEP 2: ML AND DL INFERENCE ===", flush=True)

    with latency.stage("model_inference"):
        run_inference(
            private_root,
            features,
            sha256(features),
            predictions,
        )

    result = json.loads(
        predictions.read_text(encoding="utf-8")
    )

    print("=== STEP 3: RULE REVIEW LINKAGE ===", flush=True)

    prior_dir = (
        private_root / "lab-rule-candidates" / "syn_scan_v0_1"
    )

    previous_proposal = json.loads(
        (prior_dir / "proposal.json").read_text(
            encoding="utf-8-sig"
        )
    )

    model_report = (
        private_root / "lab-models"
        / "lab_syn_anomaly_v0_1"
        / "report.json"
    )

    if (
        previous_proposal.get("status") != "needs_review"
        or previous_proposal.get("deployed") is not False
        or previous_proposal.get("model_report_sha256")
        != sha256(model_report)
    ):
        raise ValueError("Existing rule proposal provenance mismatch")

    candidate_text = (
        prior_dir / "candidate.rules"
    ).read_text(encoding="utf-8").strip()

    if (
        "sid:9102001;" not in candidate_text
        or "192.168.10.10" not in candidate_text
    ):
        raise ValueError("Unexpected original rule candidate")

    flagged = int(result["both_flagged"])

    # The old candidate is linked as experimental evidence.
    # It has already produced false alerts on Normal Test.
    attach_candidate = flagged > 0 and dst == "192.168.10.10"

    review = {
        "schema_version": "lab_rule_review_v0_1",
        "source_pcap_sha256": expected_sha.lower(),
        "feature_csv_sha256": sha256(features),
        "model_sha256": result["model_sha256"],
        "model_consensus_flagged_windows": flagged,
        "input_label": "UNLABELED",
        "status": "needs_review",
        "deployable": False,
        "deployed": False,
        "rule_generated_in_this_run": False,
        "existing_candidate_linked": attach_candidate,
        "existing_candidate_sid": (
            9102001 if attach_candidate else None
        ),
        "existing_candidate_rule": (
            candidate_text if attach_candidate else None
        ),
        "review_warning": (
            "Previously proposed SYN threshold rule generated "
            "7 false alert events on held-out Normal Test. "
            "It is blocked from live deployment."
        ),
        "next_requirement": (
            "Independent validation of a revised candidate "
            "before any deployment"
        ),
    }


    # Derive the SYN threshold ONLY from Normal train/cal data.
    reference = json.loads(
        model_report.read_text(encoding="utf-8")
    )
    normal_counts_by_partition = {}

    for partition in ("normal-train", "normal-cal"):
        reference_csv = (
            private_root / "lab-sessions" / "normal-batch-v01"
            / f"syn_windows_10s_{partition}.csv"
        )

        if sha256(reference_csv) != reference["feature_csv_sha256"][partition]:
            raise ValueError("Normal reference SHA256 mismatch")

        with reference_csv.open(
            "r", encoding="utf-8", newline=""
        ) as stream:
            reference_rows = list(csv.DictReader(stream))

        if not reference_rows:
            raise ValueError("Empty Normal reference")

        partition_counts = []
        for row in reference_rows:
            count = int(row["syn_count"])

            if (
                row["label"] != "NORMAL"
                or int(row["window_seconds"]) != 10
                or count < 1
            ):
                raise ValueError("Invalid Normal reference")

            partition_counts.append(count)
        normal_counts_by_partition[partition] = partition_counts

    normal_counts = (
        normal_counts_by_partition["normal-train"]
        + normal_counts_by_partition["normal-cal"]
    )
    normal_max = max(normal_counts)

    # Port-diversity is independent heuristic evidence.
    # It is not a learned model or an executable Suricata rule.
    syn_events = [
        event
        for event in read_pcap_syn(pcap)
        if event.src_ip == src and event.dst_ip == dst
    ]

    with latency.stage("port_diversity_extraction"):
        findings = analyze_port_diversity(
            syn_events,
            window_seconds=60,
            min_distinct_ports=8,
        )

    finding = findings[0] if findings else None

    review["port_diversity_evidence"] = {
        "method": "offline_pcap_sliding_unique_dst_ports",
        "evidence_type": "heuristic_not_ml_model",
        "source_pcap_sha256": expected_sha.lower(),
        "source_ip": src,
        "destination_ip": dst,
        "window_seconds": 60,
        "min_distinct_ports": 8,
        "total_syn_packets": (
            finding.total_syn if finding else 0
        ),
        "total_distinct_ports": (
            finding.total_distinct_ports if finding else 0
        ),
        "max_window_distinct_ports": (
            finding.max_window_distinct_ports if finding else 0
        ),
        "triggered": (
            finding.triggered if finding else False
        ),
        "first_trigger_timestamp_unix": (
            finding.first_trigger_timestamp if finding else None
        ),
        "threshold_selected_using_known_attack_normal": True,
        "independent_validation_passed": False,
        "automatic_rule_approval": False,
    }

    # Evidence must never override the existing review gate.
    review["approved"] = False
    review["deployable"] = False
    review["deployed"] = False

    # Protocol evidence is separate from ML and Port-Diversity.
    # A complete bidirectional TCP exchange is a benign-like
    # pattern, NOT proof that traffic is benign.
    with latency.stage("tcp_handshake_extraction"):
        tcp_summary = summarize_tcp_handshake(
            pcap,
            source_ip=src,
            destination_ip=dst,
        )

    if tcp_summary["initial_syn_packets"] != len(syn_events):
        raise ValueError(
            "TCP handshake and SYN evidence counts disagree"
        )

    tcp_benign_like_veto = (
        tcp_summary["syn_flows"] > 0
        and tcp_summary["flows_with_confirmed_handshake"]
        == tcp_summary["syn_flows"]
        and tcp_summary["flows_with_bidirectional_payload"]
        == tcp_summary["syn_flows"]
    )

    review["tcp_handshake_evidence"] = {
        **tcp_summary,
        "source_pcap_sha256": expected_sha.lower(),
        "benign_like_veto": tcp_benign_like_veto,
        "proves_benign": False,
        "independent_validation_passed": False,
        "interpretation": (
            "Complete TCP handshakes with bidirectional "
            "payload can also occur in malicious traffic. "
            "Incomplete captures can bias this evidence."
        ),
    }

    calibration_path = (
        Path(__file__).resolve().parents[2]
        / "configs" / "hybrid_normal_calibration.json"
    )
    calibration_provenance = {
        "manifest_path": "configs/hybrid_normal_calibration.json",
        "manifest_sha256": sha256(calibration_path) if calibration_path.is_file() else None,
        "status": "rejected",
    }
    hybrid_references = []
    try:
        provenance = load_calibration_provenance(calibration_path, private_root)
        hybrid_references = _hybrid_reference_evidence(private_root, provenance)
        calibration_provenance.update({
            "status": "accepted",
            "feature_definition": provenance["feature_definition"],
            "window_seconds": provenance["window_seconds"],
            "threshold_provenance": provenance["threshold_provenance"],
            "reference_count": len(provenance["references"]),
        })
    except (OSError, ValueError) as exc:
        calibration_provenance["rejection_reason"] = str(exc)

    if hybrid_references:
        hybrid_thresholds = calibrate_hybrid_thresholds(hybrid_references)
        with latency.stage("hybrid_evidence_extraction"):
            with latency.stage("rst_evidence_extraction"):
                rst_evidence = analyze_rst_evidence(
                    pcap,
                    source_ip=src,
                    destination_ip=dst,
                    window_seconds=60,
                    capture_metadata=_complete_capture_metadata(capture_metadata),
                )
        with latency.stage("hybrid_decision_only"):
            hybrid_result = evaluate_hybrid(
                ml_consensus=flagged > 0,
                rst_evidence=rst_evidence,
                port_evidence=review["port_diversity_evidence"],
                handshake_evidence=tcp_summary,
                thresholds=hybrid_thresholds,
            )
        review["hybrid_review"] = {
            **hybrid_result,
            "calibration_reference_count": len(hybrid_references),
            "calibration_provenance": calibration_provenance,
            "python_only": True,
            "suricata_signature_equivalent": False,
            "calibration_provenance": calibration_provenance,
        }
    else:
        latency.record("hybrid_evidence_extraction", status="not_measured")
        latency.record("rst_evidence_extraction", status="not_measured")
        latency.record("hybrid_decision_only", status="not_measured")
        review["hybrid_review"] = {
            "schema_version": "hybrid_review_v1",
            "classification": "unavailable_missing_calibration",
            "requires_manual_review": True,
            "approved": False,
            "deployable": False,
            "deployed": False,
            "python_only": True,
            "suricata_signature_equivalent": False,
            "calibration_provenance": calibration_provenance,
        }

    # AI and Port-Diversity must pass; TCP may veto.
    # Passing this gate never approves a Suricata rule.
    candidate_gate_passed = (
        flagged > 0
        and review["port_diversity_evidence"]["triggered"]
        and not tcp_benign_like_veto
        and review["hybrid_review"]["classification"] == "reconnaissance_consistent"
    )

    # Correlated detection with complete TCP traffic is ambiguous.
    # Keep the candidate gate unchanged, but preserve this signal
    # for manual review instead of treating it as proof of benignity.
    correlated_signals = (
        flagged > 0
        and review["port_diversity_evidence"]["triggered"]
    )
    ambiguous_tcp = correlated_signals and tcp_benign_like_veto

    review["triage"] = {
        "schema_version": "lab_triage_v0_1",
        "requires_manual_review": correlated_signals,
        "reason": (
            "conflicting_tcp_completion_evidence"
            if ambiguous_tcp
            else "correlated_detection_requires_rule_review"
            if correlated_signals
            else "no_correlated_detection_evidence"
        ),
        "tcp_completion_proves_benign": False,
        "auto_approve": False,
        "auto_deploy": False,
    }

    review["candidate_gate"] = {
        "method": "ai_port_diversity_tcp_benign_veto_v1",
        "ai_consensus_present": flagged > 0,
        "port_diversity_triggered": (
            review["port_diversity_evidence"]["triggered"]
        ),
        "tcp_completed_payload_veto": tcp_benign_like_veto,
        "hybrid_calibrated_reconnaissance": (
            review["hybrid_review"]["classification"]
            == "reconnaissance_consistent"
        ),
        "passed": candidate_gate_passed,
        "rule_approval_authorized": False,
    }
    review["alternative_candidate_family_review"] = {
        "family": RST_RESPONSE_FAMILY,
        "status": "integrated_gated" if candidate_gate_passed else "not_eligible",
        "reason": (
            "bounded_rst_signature_is_not_hybrid_equivalent"
            if candidate_gate_passed
            else "candidate_gate_not_passed"
        ),
        "requires_independent_native_replay": True,
        "automatic_generation": False,
        "hybrid_equivalent": False,
    }

    normal_validation = (
        private_root / "lab-sessions" / "normal-batch-v01"
        / "syn_windows_10s_normal-test.csv"
    )
    normal_test_counts = []
    if normal_validation.is_file():
        with normal_validation.open(
            "r", encoding="utf-8", newline=""
        ) as stream:
            for row in csv.DictReader(stream):
                if row.get("label") != "NORMAL":
                    raise ValueError("Normal validation contains non-NORMAL data")
                count = int(row["syn_count"])
                if count < 0:
                    raise ValueError("Normal validation contains invalid SYN count")
                normal_test_counts.append(count)

    attack_counts = [
        int(prediction["syn_count"])
        for prediction in result.get("predictions", [])
        if prediction.get("both_anomaly") is True
    ]
    generation = _candidate_generation_decision(
        candidate_gate_passed=candidate_gate_passed,
        normal_test_counts=normal_test_counts,
        attack_counts=attack_counts,
        attach_candidate=attach_candidate,
    )
    generation_rejection = generation["rejection"]
    generation_family = generation["family"]
    generated = None
    generation_detail = None
    with latency.stage("rule_generation"):
        if candidate_gate_passed and generation_rejection is None:
            try:
                development = _load_rst_development_evidence(private_root)
                validation, validation_counts = _load_rst_validation_evidence(private_root)
                threshold_provenance = calibration_provenance.get(
                    "threshold_provenance", {}
                )
                normal_calibration_provenance = {
                    "status": calibration_provenance.get("status"),
                    "manifest_sha256": calibration_provenance.get("manifest_sha256"),
                    "method": threshold_provenance.get("method"),
                    "final_holdout_used": threshold_provenance.get("final_holdout_used"),
                    "frozen_before_holdouts": threshold_provenance.get("frozen_before_holdouts"),
                    "calibration_decision_sha256": threshold_provenance.get(
                        "calibration_decision_sha256"
                    ),
                }
                attack_rst_counts = rst_evidence.get("rst_counts_by_window") or [
                    rst_evidence.get("max_rst_count_per_window", 0)
                ]
                generated = generate_rst_rule(
                    run_id=output_dir.name,
                    pcap_sha256=expected_sha.lower(),
                    model_sha256=result["model_sha256"],
                    source_ip=src,
                    destination_ip=dst,
                    normal_cal_rst_counts=development["normal_cal_rst_counts"],
                    normal_validation_rst_counts=validation_counts,
                    attack_rst_counts=attack_rst_counts,
                    ml_consensus=flagged > 0,
                    port_diversity_triggered=review["port_diversity_evidence"][
                        "triggered"
                    ],
                    rst_evidence=rst_evidence,
                    existing_sids=collect_sids([candidate_text]),
                    normal_calibration_provenance=normal_calibration_provenance,
                    normal_validation_evidence=validation,
                    development_evidence=development,
                    hybrid_evidence=review["hybrid_review"],
                )
                if generated["rule"] is not None:
                    write_rst_rule_artifacts(output_dir, generated)
                else:
                    generation_rejection = generated["rejection_reason"]
            except (OSError, KeyError, TypeError, ValueError) as exc:
                generation_rejection = "missing_or_invalid_rst_evidence"
                generation_detail = str(exc)
        elif candidate_gate_passed:
            generation_detail = generation_rejection
    if generated is None and candidate_gate_passed and generation_rejection is None:
        generation_rejection = "missing_or_invalid_rst_evidence"
    latency.record(
        "local_artifact_validation",
        status="not_measured" if generated is None else "review_only_artifacts_written",
    )

    generated_rule = generated["rule"] if generated else None
    generated_metadata = generated["metadata"] if generated else None
    generation_status = generated.get("status") if generated else None

    review.update({
        "schema_version": "lab_rule_review_v0_2",
        "generation_method": (
            "rst_response_evidence_gated"
            if generation_family == RST_RESPONSE_FAMILY and generated_rule
            else "rst_response_evidence_gated_rejected"
            if generation_family == RST_RESPONSE_FAMILY
            else "no_candidate_family_selected"
        ),
        "candidate_family": generation_family,
        "candidate_family_status": (
            "needs_review"
            if generated_rule
            else "rejected"
            if generation_family == RST_RESPONSE_FAMILY
            else None
        ),
        "normal_train_cal_max_syn": normal_max,
        "proposed_syn_threshold": max(3, normal_max + 1),
        "normal_validation_csv_sha256": (
            sha256(normal_validation) if normal_validation.is_file() else None
        ),
        "normal_validation_max_syn": (
            max(normal_test_counts) if normal_test_counts else None
        ),
        "rule_generated_in_this_run": bool(generated_rule),
        "generated_rule": generated_rule,
        "generated_rule_sid": generated["sid"] if generated else None,
        "generated_rule_family": generation_family,
        "generated_rule_metadata": generated_metadata,
        "matches_previous_failed_candidate": generation[
            "matches_previous_failed_candidate"
        ],
        "generation_rejection": generation_rejection,
        "generation_detail": generation_detail,
        "status": (
            generation_status
            if generated_rule
            else "rejected_validation_failure"
            if generation_rejection
            else "no_candidate"
        ),
        "syntax_tested_in_this_run": False,
        "normal_replay_tested_in_this_run": False,
        "deployable": False,
        "deployed": False,
    })

    latency.record("owner_approval", status="not_measured")
    latency.record("rule_load", status="not_measured")
    latency.record("first_alert", status="not_measured")
    latency.record("rollback", status="not_measured")
    latency_path = output_dir / "latency-trace.json"
    with latency_path.open("x", encoding="utf-8") as stream:
        json.dump(latency.as_dict(), stream, indent=2)
        stream.write("\n")
    review["latency_trace_path"] = latency_path.name
    review["latency_trace_sha256"] = sha256(latency_path)

    with review_path.open("x", encoding="utf-8") as stream:
        json.dump(review, stream, indent=2)
        stream.write("\n")

    print("Consensus anomalous windows:", flagged)
    print("Existing rule linked:", attach_candidate)
    print("Rule deployment: BLOCKED")
    print("Output:", output_dir)
    print("PASS: PCAP ML DL REVIEW PIPELINE")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--pcap-sha256", required=True)
    parser.add_argument("--src", required=True)
    parser.add_argument("--dst", required=True)
    parser.add_argument(
        "--private-root",
        type=Path,
        default=Path("data/private"),
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        required=True,
    )
    args = parser.parse_args()

    run(
        args.pcap,
        args.pcap_sha256,
        args.src,
        args.dst,
        args.private_root,
        args.out_dir,
    )


if __name__ == "__main__":
    main()
