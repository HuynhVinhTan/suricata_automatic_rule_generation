from pathlib import PurePosixPath

import pytest

from scripts.runtime_orchestration_contract import (
    CAPTURE_SERVICE,
    build_vm1_capture_readiness_script,
    build_worker_argv,
    capture_bundle_paths,
    correlate_capture_and_generator,
    g3_release_paths,
    worker_bundle_paths,
)


def test_capture_readiness_is_nonblocking_and_never_launches_generator():
    script = build_vm1_capture_readiness_script()
    assert f"sudo systemctl start --no-block {CAPTURE_SERVICE}" in script
    assert "ActiveState" in script and "SubState" in script
    assert "[t]cpdump -i ens33 -s 262144" in script
    assert "lab_slow_port_scan" not in script
    assert "python" not in script
    assert "systemctl start " + CAPTURE_SERVICE + "\n" not in script


def test_sealed_bundle_paths_use_backend_capture_id():
    paths = capture_bundle_paths("capture-20261123T120000Z-0123456789abcdef")
    assert paths == (
        "/home/tanhv/suricata-ai-outbox/capture-20261123T120000Z-0123456789abcdef/"
        "capture-20261123T120000Z-0123456789abcdef.pcap",
        "/home/tanhv/suricata-ai-outbox/capture-20261123T120000Z-0123456789abcdef/"
        "capture-20261123T120000Z-0123456789abcdef.manifest.json",
        "/home/tanhv/suricata-ai-outbox/capture-20261123T120000Z-0123456789abcdef/"
        "capture-20261123T120000Z-0123456789abcdef.ready.json",
    )
    assert all("capture.pcap" not in path for path in paths)
    with pytest.raises(ValueError):
        capture_bundle_paths("g4-attack-20261123T120000Z-0123456789abcdef")


def test_vm3_worker_bundle_is_flat_after_handoff():
    paths = worker_bundle_paths(
        "capture-20261123T120000Z-0123456789abcdef",
        input_root=PurePosixPath("/home/tanhv/verified-inbox"),
    )
    assert paths == (
        "/home/tanhv/verified-inbox/capture-20261123T120000Z-0123456789abcdef.pcap",
        "/home/tanhv/verified-inbox/capture-20261123T120000Z-0123456789abcdef.manifest.json",
        "/home/tanhv/verified-inbox/capture-20261123T120000Z-0123456789abcdef.ready.json",
    )
    assert all("/capture-20261123T120000Z-0123456789abcdef/" not in path for path in paths)


def test_capture_and_generator_identity_are_correlated_not_renamed():
    result = correlate_capture_and_generator(
        "capture-20261123T120000Z-0123456789abcdef",
        "g4-attack-20261123T120001Z-fedcba9876543210",
    )
    assert result["capture_id"].startswith("capture-")
    assert result["generator_id"].startswith("g4-")
    with pytest.raises(ValueError):
        correlate_capture_and_generator(
            "capture-20261123T120000Z-0123456789abcdef",
            "capture-20261123T120000Z-0123456789abcdef",
        )


def test_worker_argv_has_input_root_manifest_and_private_root():
    argv = build_worker_argv(
        "capture-20261123T120000Z-0123456789abcdef",
        input_root=PurePosixPath("/home/tanhv/ai-inbox"),
        private_root=PurePosixPath("/home/tanhv/ai-private"),
    )
    assert argv[0:3] == ["/home/tanhv/suricata-ai-venv/bin/python", "-m", "backend.worker"]
    assert "--input-root" in argv
    assert "--private-root" in argv
    assert "--manifest" in argv
    assert "capture.pcap" not in argv
    assert argv[argv.index("--run-id") + 1] == "capture-20261123T120000Z-0123456789abcdef"
    assert argv[argv.index("--pcap") + 1] == (
        "/home/tanhv/ai-inbox/capture-20261123T120000Z-0123456789abcdef.pcap"
    )
    assert argv[argv.index("--manifest") + 1] == (
        "/home/tanhv/ai-inbox/capture-20261123T120000Z-0123456789abcdef.manifest.json"
    )


def test_g3_sync_is_versioned_and_private_key_is_not_in_release():
    paths = g3_release_paths(host_root=PurePosixPath("/home/tanhv/suricata-ai-showcase"))
    assert paths["release"].endswith("/releases/d1005c24f94c3d994a9fff7cdb780c4ca90b3daa")
    assert "/current/" not in paths["release"]
    assert paths["private_key"].endswith("/private/g3/g3-signer.pem")
    assert paths["private_key"] not in paths["release"]
    assert paths["ledger"].endswith("/private/g3/g3-replay.sqlite3")
    assert paths["fingerprint"].endswith("/private/g3/g3-signer.pub.sha256")
    assert paths["record"].endswith("/evidence/g3/record.json")
