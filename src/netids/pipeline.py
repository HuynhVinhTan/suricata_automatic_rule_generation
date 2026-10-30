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
from netids.rulegen import build_syn_burst_review_rule
from netids.port_diversity import analyze_port_diversity, read_pcap_syn


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
    normal_counts = []

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

        for row in reference_rows:
            count = int(row["syn_count"])

            if (
                row["label"] != "NORMAL"
                or int(row["window_seconds"]) != 10
                or count < 1
            ):
                raise ValueError("Invalid Normal reference")

            normal_counts.append(count)

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

    # Both signals are required to propose a candidate.
    # Passing this gate never approves a Suricata rule.
    candidate_gate_passed = (
        flagged > 0
        and review["port_diversity_evidence"]["triggered"]
    )

    review["candidate_gate"] = {
        "method": "ai_consensus_and_port_diversity",
        "ai_consensus_present": flagged > 0,
        "port_diversity_triggered": (
            review["port_diversity_evidence"]["triggered"]
        ),
        "passed": candidate_gate_passed,
        "rule_approval_authorized": False,
    }

    generated_rule = (
        build_syn_burst_review_rule(
            destination_ip=dst,
            normal_max_syn=normal_max,
        )
        if candidate_gate_passed
        else None
    )

    matches_failed = (
        generated_rule is not None
        and generated_rule == candidate_text
    )

    if generated_rule is not None:
        (output_dir / "candidate.rules").write_text(
            generated_rule + "\n", encoding="utf-8"
        )

    review.update({
        "schema_version": "lab_rule_review_v0_2",
        "generation_method": "normal_train_cal_syn_count_proxy",
        "normal_train_cal_max_syn": normal_max,
        "proposed_syn_threshold": max(3, normal_max + 1),
        "rule_generated_in_this_run": generated_rule is not None,
        "generated_rule": generated_rule,
        "matches_previous_failed_candidate": matches_failed,
        "status": (
            "rejected_known_false_positive"
            if matches_failed
            else "needs_review"
            if generated_rule is not None
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