"""Execute verified isolated Suricata replays and sign the resulting evidence."""
from __future__ import annotations

import argparse
import getpass
import json
from pathlib import Path

from backend.replay_attestation_service import ReplayAttestationService


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("private-key", "rule", "attack-pcap", "normal-pcap", "runtime-config", "output-dir"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--attack-pcap-sha256", required=True)
    parser.add_argument("--normal-pcap-sha256", required=True)
    parser.add_argument("--runtime-config-sha256", required=True)
    parser.add_argument("--sid", type=int, required=True)
    parser.add_argument("--rule-sha256", required=True)
    parser.add_argument("--model-sha256", required=True)
    parser.add_argument("--calibration-sha256", required=True)
    parser.add_argument("--decision-manifest-sha256", required=True)
    args = parser.parse_args(argv)
    password = getpass.getpass("Replay signing key passphrase (leave blank if unencrypted): ").encode() or None
    service = ReplayAttestationService(
        private_key=args.private_key, expected_sid=args.sid, expected_rule_sha256=args.rule_sha256,
        expected_model_sha256=args.model_sha256, expected_calibration_sha256=args.calibration_sha256,
        expected_decision_manifest_sha256=args.decision_manifest_sha256,
    )
    record, signature = service.attest_from_execution(
        rule_path=args.rule, attack_pcap=args.attack_pcap, normal_pcap=args.normal_pcap,
        attack_pcap_sha256=args.attack_pcap_sha256, normal_pcap_sha256=args.normal_pcap_sha256,
        runtime_config=args.runtime_config, runtime_config_sha256=args.runtime_config_sha256,
        output_dir=args.output_dir, password=password,
    )
    record["attestation_signature"] = signature
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "replay-attestation.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    (args.output_dir / "replay-attestation.sig").write_text(signature + "\n", encoding="ascii")
    print(json.dumps({"status": "SIGNED", "path": str(args.output_dir / "replay-attestation.json")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
