"""Interactively sign one exact isolated activation-and-rollback authorization."""
from __future__ import annotations
import argparse, getpass, json, secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from backend.owner_approval_service import create_owner_approval


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--replay-evidence-sha256", required=True)
    parser.add_argument("--approver-identity", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    candidate = json.loads(args.candidate.read_text(encoding="utf-8"))
    now = datetime.now(timezone.utc)
    print(json.dumps({"candidate_id": candidate["candidate_id"], "sid": candidate["sid"], "rule_sha256": candidate["rule_sha256"], "target": "suricata-vm1 isolated-lifecycle-9103003 lo", "operation": "activate_once_then_rollback", "production": "EXCLUDED", "rollback": "remove SID, reload isolated socket, verify no alert, stop daemon"}, indent=2))
    confirmation = input("Type ACTIVATE_ONCE_THEN_ROLLBACK to continue: ")
    password = getpass.getpass("Owner key passphrase: ").encode() or None
    record, signature = create_owner_approval(
        private_key=args.private_key, candidate=candidate, target_vm="suricata-vm1",
        isolated_runtime_id="isolated-lifecycle-9103003", interface="lo",
        operation="activate_once_then_rollback", approver_identity=args.approver_identity,
        replay_evidence_sha256=args.replay_evidence_sha256, approved_at=now,
        expires_at=now + timedelta(minutes=15), nonce=secrets.token_hex(16),
        confirmation=confirmation, password=password,
    )
    record["attestation_signature"] = signature
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "owner-approval.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    (args.output_dir / "owner-approval.sig").write_text(signature + "\n", encoding="ascii")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
