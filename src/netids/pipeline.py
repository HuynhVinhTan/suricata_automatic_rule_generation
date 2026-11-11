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
    build_syn_burst_review_rule,
    collect_sids,
    generate_ml_rule,
    write_ml_rule_artifacts,
)
from netids.port_diversity import analyze_port_diversity, read_pcap_syn
from netids.tcp_handshake import summarize_tcp_handshake


def run(pcap, expected_sha, src, dst, private_root, output_dir):
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

    features = output_dir / "syn_windows.csv"
    predictions = output_dir / "predictions.json"
    review_path = output_dir / "review.json"

    print("=== STEP 1: PCAP TO SYN FEATURES ===", flush=True)

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

    # AI and Port-Diversity must pass; TCP may veto.
    # Passing this gate never approves a Suricata rule.
    candidate_gate_passed = (
        flagged > 0
        and review["port_diversity_evidence"]["triggered"]
        and not tcp_benign_like_veto
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
        "passed": candidate_gate_passed,
        "rule_approval_authorized": False,
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
    existing_sids = collect_sids(
        path.read_text(encoding="utf-8")
        for path in private_root.rglob("*.rules")
        if path.is_file()
    )

    generated = None
    generation_rejection = None
    if candidate_gate_passed and not normal_test_counts:
        generation_rejection = "missing_normal_validation"
    elif candidate_gate_passed and not attack_counts:
        generation_rejection = "missing_attack_inference_evidence"
    elif candidate_gate_passed:
        generated = generate_ml_rule(
            run_id=output_dir.name,
            pcap_sha256=expected_sha,
            model_sha256=result["model_sha256"],
            destination_ip=dst,
            normal_train_syn_counts=normal_counts_by_partition["normal-train"],
            normal_cal_syn_counts=normal_counts_by_partition["normal-cal"],
            normal_test_syn_counts=normal_test_counts,
            attack_syn_counts=attack_counts,
            existing_sids=existing_sids,
        )
        if generated["rule"] is not None:
            write_ml_rule_artifacts(output_dir, generated)

    review.update({
        "schema_version": "lab_rule_review_v0_2",
        "generation_method": "normal_train_cal_syn_count_packet_filter",
        "normal_train_cal_max_syn": normal_max,
        "proposed_syn_threshold": max(3, normal_max + 1),
        "normal_validation_csv_sha256": (
            sha256(normal_validation) if normal_validation.is_file() else None
        ),
        "normal_validation_max_syn": (
            max(normal_test_counts) if normal_test_counts else None
        ),
        "rule_generated_in_this_run": bool(generated and generated["rule"]),
        "generated_rule": generated["rule"] if generated else None,
        "generated_rule_sid": generated["sid"] if generated else None,
        "generated_rule_metadata": generated["metadata"] if generated else None,
        "matches_previous_failed_candidate": False,
        "generation_rejection": generation_rejection or (
            generated.get("rejection_reason") if generated else None
        ),
        "status": (
            "needs_review" if generated and generated["rule"]
            else "rejected_validation_failure"
            if generation_rejection or generated
            else "no_candidate"
        ),
        "syntax_tested_in_this_run": False,
        "normal_replay_tested_in_this_run": False,
        "deployable": False,
        "deployed": False,
    })

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
