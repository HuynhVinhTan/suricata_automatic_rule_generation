import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).parents[1]
DEMO = ROOT / "scripts" / "demo"


def test_candidate_validator_canonicalizes_each_input_independently():
    source = (DEMO / "vm1-validate-candidate.sh").read_text()

    assert "realpath -e" in source
    assert "CONFIG" in source and "RULES" in source and "PCAP" in source
    assert source.count("canonicalize_input") >= 4
    assert "rule-files" in source
    assert "RULES" in source and "not referenced" in source


def test_rollback_requires_candidate_removal_negative_replay_and_invariants():
    source = (DEMO / "vm1-isolated-rollback.sh").read_text()

    assert "ROLLBACK_NOT_VERIFIED" in source
    assert "candidate" in source.lower()
    assert "negative" in source.lower()
    assert "production" in source.lower()
    for field in ("candidate_id", "candidate_sid", "rule_sha256", "pcap_sha256", "run_id", "post_rollback_timestamp"):
        assert field in source


def test_relay_rotation_keeps_jsonl_records_intact(tmp_path):
    records = [{"event_id": str(i), "payload": "x" * 20} for i in range(5)]
    output = tmp_path / "shadow"
    proc = subprocess.run(
        ["python", str(DEMO / "vm3-relay-sink.py"), "--root", str(output), "--max-file-bytes", "70"],
        input=("".join(json.dumps(item) + "\n" for item in records)).encode(),
        capture_output=True,
    )

    assert proc.returncode == 0
    files = sorted(output.glob("eve-shadow.jsonl*"), key=lambda path: (1 if path.name == "eve-shadow.jsonl" else 0, 0 if path.name == "eve-shadow.jsonl" else int(path.suffix[1:])))
    actual = [json.loads(line) for path in files for line in path.read_text().splitlines()]
    assert actual == records


def test_stop_script_does_not_expand_remote_shell_variables_locally():
    source = (ROOT / "scripts" / "demo" / "windows" / "Stop-Showcase.ps1").read_text()

    assert "`$HOME" not in source
    assert "`$p" not in source
    assert "ssh -o BatchMode=yes" in source
    assert " $command" in source
    assert "worker.pid" in source


def test_normal_service_publishes_the_health_resource():
    source = (DEMO / "vm1-start-normal-service.sh").read_text()

    assert "health" in source
    assert "18080" in source


def test_relay_has_a_total_storage_cap_and_fail_closed_exit():
    source = (DEMO / "vm3-relay-sink.py").read_text()

    assert "max-total-bytes" in source
    assert "MAX_TOTAL_BYTES" in source
    assert "fail" in source.lower() or "SystemExit" in source


def test_relay_fails_closed_at_total_storage_cap(tmp_path):
    output = tmp_path / "shadow"
    payload = b'{"event_id":"1","value":"xxxxxxxxxxxxxxxxxxxxxxxx"}\n'
    proc = subprocess.run(
        ["python", str(DEMO / "vm3-relay-sink.py"), "--root", str(output), "--max-file-bytes", "64", "--max-total-bytes", "64"],
        input=payload + payload,
        capture_output=True,
    )

    assert proc.returncode == 75
    assert b"RELAY_STORAGE_CAP_REACHED" in proc.stderr
