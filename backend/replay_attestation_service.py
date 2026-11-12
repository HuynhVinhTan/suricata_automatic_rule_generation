"""Ed25519 replay attestation for independently verified isolated Suricata runs."""
from __future__ import annotations

import base64
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


class ReplayAttestationError(ValueError):
    pass


def canonical_json(value: dict) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ReplayAttestationError("Evidence is not canonicalizable") from exc


def signed_payload(value: dict, domain: str) -> bytes:
    return b"suricata-ai:" + domain.encode("ascii") + b"\0" + canonical_json({k: v for k, v in value.items() if k != "attestation_signature"})


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_private(path: Path, password: bytes | None = None) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(Path(path).read_bytes(), password=password)
    except (OSError, ValueError, TypeError) as exc:
        raise ReplayAttestationError("Unable to load replay signing key") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ReplayAttestationError("Replay signing key must be Ed25519")
    return key


def _load_public(path: Path) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(Path(path).read_bytes())
    except (OSError, ValueError, TypeError) as exc:
        raise ReplayAttestationError("Unable to load pinned replay public key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ReplayAttestationError("Pinned replay key must be Ed25519")
    return key


class ReplayAttestationService:
    def __init__(self, *, private_key: Path, expected_sid: int, expected_rule_sha256: str,
                 expected_model_sha256: str, expected_calibration_sha256: str,
                 expected_decision_manifest_sha256: str, expected_suricata_version: str = "8.0.3 RELEASE"):
        self.private_key = Path(private_key)
        self.expected = {
            "sid": expected_sid, "rule_sha256": expected_rule_sha256,
            "model_sha256": expected_model_sha256, "calibration_sha256": expected_calibration_sha256,
            "decision_manifest_sha256": expected_decision_manifest_sha256,
            "suricata_version": expected_suricata_version,
        }

    @staticmethod
    def sign_record(record: dict, private_key: Path, password: bytes | None = None) -> str:
        payload = signed_payload(record, "isolated-replay-v1")
        return base64.b64encode(_load_private(private_key, password).sign(payload)).decode("ascii")

    def attest_from_verified_results(self, results: dict) -> dict:
        """Deliberately unavailable: caller booleans are never trusted as replay evidence."""
        raise ReplayAttestationError("Signer does not accept caller-provided replay booleans")

    def _verify_rule_and_provenance(self, rule_path: Path, provenance: dict) -> str:
        rule = Path(rule_path).read_text(encoding="utf-8").strip()
        actual_rule_sha = hashlib.sha256(rule.encode("utf-8")).hexdigest()
        if actual_rule_sha != self.expected["rule_sha256"]:
            raise ReplayAttestationError("Candidate rule SHA256 mismatch")
        if provenance != {key: self.expected[key] for key in ("sid", "model_sha256", "calibration_sha256", "decision_manifest_sha256", "suricata_version")}:
            raise ReplayAttestationError("Pinned candidate provenance mismatch")
        return actual_rule_sha

    @staticmethod
    def _alerts(eve_path: Path, sid: int) -> tuple[int, int]:
        alerts = 0
        flows = set()
        with Path(eve_path).open(encoding="utf-8") as stream:
            for line in stream:
                if not line.strip():
                    continue
                event = json.loads(line)
                alert = event.get("alert")
                if event.get("event_type") == "alert" and isinstance(alert, dict) and alert.get("signature_id") == sid:
                    alerts += 1
                    if event.get("flow_id") is not None:
                        flows.add(event["flow_id"])
        return alerts, len(flows)

    def attest_from_execution(self, *, rule_path: Path, attack_pcap: Path, normal_pcap: Path,
                              attack_pcap_sha256: str, normal_pcap_sha256: str,
                              runtime_config: Path, runtime_config_sha256: str,
                              output_dir: Path, suricata_bin: str = "suricata",
                              password: bytes | None = None) -> tuple[dict, str]:
        """Run syntax validation and both replays, then sign only verified outcomes."""
        if sha256_file(attack_pcap) != attack_pcap_sha256 or sha256_file(normal_pcap) != normal_pcap_sha256:
            raise ReplayAttestationError("Source PCAP SHA256 mismatch")
        if sha256_file(runtime_config) != runtime_config_sha256:
            raise ReplayAttestationError("Runtime configuration SHA256 mismatch")
        rule_sha = self._verify_rule_and_provenance(rule_path, self.expected)
        output_dir = Path(output_dir); output_dir.mkdir(parents=True, exist_ok=True)
        syntax_dir = output_dir / "syntax"; syntax_dir.mkdir(exist_ok=True)
        syntax_command = [suricata_bin, "-T", "-c", str(runtime_config), "-S", str(rule_path), "-l", str(syntax_dir)]
        syntax = subprocess.run(syntax_command, capture_output=True, text=True, check=False)
        if syntax.returncode != 0:
            raise ReplayAttestationError("Suricata syntax validation failed")
        version = subprocess.run([suricata_bin, "--build-info"], capture_output=True, text=True, check=False)
        version_text = (version.stdout + version.stderr).strip()
        if self.expected["suricata_version"] not in version_text:
            raise ReplayAttestationError("Unexpected Suricata version")
        outcomes = {}
        for label, pcap in (("attack", attack_pcap), ("normal", normal_pcap)):
            replay_dir = output_dir / label; replay_dir.mkdir(exist_ok=True)
            command = [suricata_bin, "-r", str(pcap), "-c", str(runtime_config), "-S", str(rule_path), "-l", str(replay_dir), "-k", "none"]
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            if result.returncode != 0:
                raise ReplayAttestationError(f"{label.title()} replay failed")
            eve = replay_dir / "eve.json"
            if not eve.is_file():
                raise ReplayAttestationError(f"Missing {label} EVE output")
            alerts, flows = self._alerts(eve, self.expected["sid"])
            outcomes[label] = {"alerts": alerts, "flows": flows, "eve_sha256": sha256_file(eve), "pcap_sha256": sha256_file(pcap), "command": command}
        if outcomes["attack"]["alerts"] < 1 or outcomes["normal"]["alerts"] != 0:
            raise ReplayAttestationError("Attack/Normal replay gate failed")
        record = {"schema_version": "suricata_replay_attestation_v1", "verified": True,
                  "verified_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                  "sid": self.expected["sid"], "rule_sha256": rule_sha,
                  "runtime_config_sha256": runtime_config_sha256, "suricata_version": version_text,
                  "syntax_command": syntax_command, "syntax_returncode": syntax.returncode,
                  "attack": outcomes["attack"], "normal": outcomes["normal"]}
        return record, self.sign_record(record, self.private_key, password)


def verify_replay_attestation(record_path: Path, signature_path: Path, public_key: Path) -> bool:
    try:
        record = json.loads(Path(record_path).read_text(encoding="utf-8"))
        signature = base64.b64decode(Path(signature_path).read_text(encoding="ascii").strip(), validate=True)
        _load_public(public_key).verify(signature, signed_payload(record, "isolated-replay-v1"))
        return record.get("schema_version") == "suricata_replay_attestation_v1" and record.get("verified") is True
    except (OSError, ValueError, TypeError, UnicodeError, InvalidSignature):
        return False
