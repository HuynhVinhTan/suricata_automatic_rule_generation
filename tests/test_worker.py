import hashlib
import json
import os
import subprocess
import urllib.error
from pathlib import Path
from types import SimpleNamespace

import pytest

from netids import pipeline
from netids.lab_runtime import FEATURES
from netids.rulegen import build_syn_burst_review_rule
from backend import worker


SRC = "192.168.10.20"
DST = "192.168.10.10"
FEATURE_CSV = (
    "label,window_index,window_seconds,syn_count,unique_dst_ports\n"
    "UNLABELED,0,10,1,1\n"
)
SOURCE_PCAP_SHA256 = hashlib.sha256(b"synthetic-pcap").hexdigest()
FEATURE_CSV_SHA256 = hashlib.sha256(FEATURE_CSV.encode("utf-8")).hexdigest()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _prepare_private(root: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        worker.shutil,
        "disk_usage",
        lambda _: SimpleNamespace(total=10**10, used=0, free=10**10),
    )
    sessions = root / "lab-sessions" / "normal-batch-v01"
    sessions.mkdir(parents=True)

    reference_hashes = {}
    for partition in ("normal-train", "normal-cal"):
        reference = sessions / f"syn_windows_10s_{partition}.csv"
        reference.write_text(
            "label,window_seconds,syn_count\nNORMAL,10,1\n",
            encoding="utf-8",
        )
        reference_hashes[partition] = _sha256(reference)

    model_dir = root / "lab-models" / "lab_syn_anomaly_v0_1"
    model_dir.mkdir(parents=True)
    model_path = model_dir / "models.joblib"
    model_path.write_bytes(b"synthetic-frozen-model")
    report_path = model_dir / "report.json"
    report_path.write_text(
        json.dumps({
            "experiment": "lab_syn_anomaly_v0_1",
            "training_policy": "NORMAL_ONLY",
            "feature_names": FEATURES,
            "window_seconds": 10,
            "thresholds": {
                "IsolationForest": 0.1,
                "NumpyAutoencoder": 0.2,
            },
            "feature_csv_sha256": reference_hashes,
        }),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        worker, "EXPECTED_MODEL_SHA256", _sha256(model_path), raising=False
    )

    proposal_dir = root / "lab-rule-candidates" / "syn_scan_v0_1"
    proposal_dir.mkdir(parents=True)
    (proposal_dir / "candidate.rules").write_text(
        build_syn_burst_review_rule(
            destination_ip=DST,
            normal_max_syn=1,
        )
        + "\n",
        encoding="utf-8",
    )
    (proposal_dir / "proposal.json").write_text(
        json.dumps({
            "status": "needs_review",
            "deployed": False,
            "model_report_sha256": _sha256(report_path),
        }),
        encoding="utf-8",
    )


def _input(tmp_path: Path):
    input_root = tmp_path / "incoming"
    input_root.mkdir()
    pcap = input_root / "input.pcap"
    pcap.write_bytes(b"synthetic-pcap")

    private = tmp_path / "private"
    private.mkdir()
    output_dir = private / "lab-runs" / "run-001"

    return {
        "pcap": pcap,
        "input_root": input_root,
        "src": SRC,
        "dst": DST,
        "private_root": private,
        "run_id": "run-001",
        "output_dir": output_dir,
        "expected_sha": _sha256(pcap),
    }


def _valid_review(status="needs_review", **overrides):
    review = {
        "schema_version": "lab_rule_review_v0_2",
        "source_pcap_sha256": SOURCE_PCAP_SHA256,
        "feature_csv_sha256": FEATURE_CSV_SHA256,
        "status": status,
        "approved": False,
        "deployable": False,
        "deployed": False,
        "triage": {"auto_approve": False, "auto_deploy": False},
        "candidate_gate": {"rule_approval_authorized": False},
        "hybrid_review": {
            "schema_version": "hybrid_review_v1",
            "classification": "unavailable_missing_calibration",
            "requires_manual_review": True,
            "approved": False,
            "deployable": False,
            "deployed": False,
            "python_only": True,
            "suricata_signature_equivalent": False,
            "calibration_provenance": {"status": "rejected"},
        },
        "model_sha256": worker.EXPECTED_MODEL_SHA256,
    }
    review.update(overrides)
    return review


def _successful_processor(
    review=None, *, prediction_overrides=None, omit_prediction_fields=()
):
    def process(pcap, expected_sha, src, dst, private_root, output_dir):
        assert isinstance(pcap, Path)
        output_dir.mkdir(parents=True, exist_ok=False)
        feature_path = output_dir / "syn_windows.csv"
        feature_path.write_bytes(FEATURE_CSV.encode("utf-8"))
        if review is not None:
            (output_dir / "review.json").write_text(
                json.dumps(review), encoding="utf-8"
            )
        predictions = {
            "input_sha256": _sha256(feature_path),
            "training_performed": False,
            "suricata_rule_generated": False,
            "rule_deployed": False,
            "model_sha256": worker.EXPECTED_MODEL_SHA256,
            "windows": 1,
            "isolation_forest_flagged": 0,
            "autoencoder_flagged": 0,
            "both_flagged": 0,
        }
        predictions.update(prediction_overrides or {})
        for field in omit_prediction_fields:
            predictions.pop(field, None)
        (output_dir / "predictions.json").write_text(
            json.dumps(predictions),
            encoding="utf-8",
        )
    return process


def test_worker_calls_real_pipeline_with_path(tmp_path, monkeypatch):
    values = _input(tmp_path)
    _prepare_private(values["private_root"], monkeypatch)

    def fake_extract(command, check):
        assert check is True
        features = Path(command[command.index("--out") + 1])
        features.write_text(
            "label,window_index,window_seconds,syn_count,unique_dst_ports\n"
            "UNLABELED,0,10,1,1\n",
            encoding="utf-8",
        )

    def fake_inference(private_root, feature_path, feature_sha, output):
        assert isinstance(private_root, Path)
        assert isinstance(feature_path, Path)
        output.write_text(
            json.dumps({
                "both_flagged": 0,
                "model_sha256": worker.EXPECTED_MODEL_SHA256,
                "input_sha256": feature_sha,
                "training_performed": False,
                "suricata_rule_generated": False,
                "rule_deployed": False,
                "windows": 1,
                "isolation_forest_flagged": 0,
                "autoencoder_flagged": 0,
            }),
            encoding="utf-8",
        )

    monkeypatch.setattr(pipeline.subprocess, "run", fake_extract)
    monkeypatch.setattr(pipeline, "run_inference", fake_inference)
    monkeypatch.setattr(pipeline, "read_pcap_syn", lambda path: [])
    monkeypatch.setattr(
        pipeline,
        "summarize_tcp_handshake",
        lambda *args, **kwargs: {
            "initial_syn_packets": 0,
            "syn_flows": 0,
            "flows_with_confirmed_handshake": 0,
            "flows_with_bidirectional_payload": 0,
            "flows_with_server_payload": 0,
            "method": "test",
            "evidence_type": "test",
        },
    )

    values["processor"] = pipeline.run
    summary = worker.run_worker(**values)

    assert summary["status"] == "succeeded"
    assert summary["review_status"] == "no_candidate"
    assert (values["output_dir"] / "review.json").is_file()


def test_pipeline_exception_before_output_preserves_exception(tmp_path, monkeypatch):
    values = _input(tmp_path)
    _prepare_private(values["private_root"], monkeypatch)
    original = RuntimeError("pipeline failed before output creation")

    def fail_before_mkdir(*args):
        raise original

    values["processor"] = fail_before_mkdir
    with pytest.raises(RuntimeError) as caught:
        worker.run_worker(**values)

    assert caught.value is original
    failure = values["private_root"] / "lab-failures" / "run-001.json"
    assert json.loads(failure.read_text(encoding="utf-8"))["status"] == "failed"


def test_cli_returns_nonzero_when_processing_fails(monkeypatch, capsys, tmp_path):
    failure = RuntimeError("worker failed")
    monkeypatch.setattr(worker, "run_worker", lambda **kwargs: (_ for _ in ()).throw(failure))
    result = worker.main([
        "--pcap", str(tmp_path / "input.pcap"),
        "--input-root", str(tmp_path),
        "--src", SRC,
        "--dst", DST,
        "--private-root", str(tmp_path),
        "--run-id", "run-001",
        "--expected-sha256", "0" * 64,
    ])
    assert result != 0
    assert "worker failed" not in capsys.readouterr().out


@pytest.mark.parametrize("review_contents", [None, "{invalid json"])
def test_missing_or_malformed_review_fails_closed(tmp_path, monkeypatch, review_contents):
    values = _input(tmp_path)
    _prepare_private(values["private_root"], monkeypatch)

    def process(*args):
        values["output_dir"].mkdir(parents=True, exist_ok=False)
        if review_contents is not None:
            (values["output_dir"] / "review.json").write_text(
                review_contents, encoding="utf-8"
            )

    values["processor"] = process
    with pytest.raises(worker.WorkerProcessingError):
        worker.run_worker(**values)
    summary = json.loads(
        (values["output_dir"] / "worker_summary.json").read_text(
            encoding="utf-8"
        )
    )
    assert summary["status"] == "failed"


@pytest.mark.parametrize(
    "overrides",
    [
        {"approved": True},
        {"deployable": True},
        {"deployed": True},
        {"auto_approve": True},
        {"auto_deploy": True},
        {"approved": "false"},
        {"triage": {"auto_approve": True}},
        {"triage": {"auto_deploy": True}},
    ],
)
def test_review_approval_or_deployment_claim_is_rejected(
    tmp_path, monkeypatch, overrides
):
    values = _input(tmp_path)
    _prepare_private(values["private_root"], monkeypatch)
    values["processor"] = _successful_processor(
        _valid_review(**overrides)
    )
    with pytest.raises(worker.WorkerProcessingError):
        worker.run_worker(**values)


@pytest.mark.parametrize("field", ["approved", "deployable", "deployed"])
def test_v0_2_review_requires_top_level_safety_fields(field):
    review = _valid_review()
    review.pop(field)

    with pytest.raises(worker.WorkerProcessingError, match=field):
        worker._review_is_safe(review)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("triage", None),
        ("triage", "not-an-object"),
        ("candidate_gate", None),
        ("candidate_gate", "not-an-object"),
    ],
)
def test_review_rejects_missing_or_malformed_safety_objects(field, value):
    review = _valid_review()
    if value is None:
        review.pop(field)
    else:
        review[field] = value

    with pytest.raises(worker.WorkerProcessingError, match=field):
        worker._review_is_safe(review)


@pytest.mark.parametrize(
    ("object_name", "field"),
    [
        ("triage", "auto_approve"),
        ("triage", "auto_deploy"),
        ("candidate_gate", "rule_approval_authorized"),
    ],
)
def test_review_requires_nested_safety_fields(object_name, field):
    review = _valid_review()
    review[object_name].pop(field)

    with pytest.raises(worker.WorkerProcessingError, match=field):
        worker._review_is_safe(review)


@pytest.mark.parametrize(
    "value",
    ["false", 0, 1, None, [], {}],
)
@pytest.mark.parametrize(
    ("object_name", "field"),
    [
        ("review", "approved"),
        ("review", "deployable"),
        ("review", "deployed"),
        ("triage", "auto_approve"),
        ("triage", "auto_deploy"),
        ("candidate_gate", "rule_approval_authorized"),
    ],
)
def test_review_requires_exact_false_for_safety_fields(
    object_name, field, value
):
    review = _valid_review()
    target = review if object_name == "review" else review[object_name]
    target[field] = value

    with pytest.raises(worker.WorkerProcessingError):
        worker._review_is_safe(review)


def test_valid_v0_2_review_is_accepted():
    assert worker._review_is_safe(_valid_review()) == "needs_review"


def test_v0_2_review_requires_explicit_hybrid_result():
    review = _valid_review()
    review.pop("hybrid_review", None)
    with pytest.raises(worker.WorkerProcessingError, match="hybrid"):
        worker._review_is_safe(review)


def test_hybrid_review_tampering_is_rejected():
    review = _valid_review()
    review["hybrid_review"] = {
        "schema_version": "hybrid_review_v1",
        "classification": "unavailable_missing_calibration",
        "requires_manual_review": True,
        "approved": True,
        "deployable": False,
        "deployed": False,
        "python_only": True,
        "suricata_signature_equivalent": False,
    }
    with pytest.raises(worker.WorkerProcessingError, match="hybrid"):
        worker._review_is_safe(review)


def test_supported_v0_1_review_uses_legacy_schema_contract():
    review = _valid_review()
    review["schema_version"] = "lab_rule_review_v0_1"
    review.pop("approved")

    assert worker._review_is_safe(review) == "needs_review"


def test_historical_v0_1_review_can_omit_hybrid_result():
    review = _valid_review()
    review["schema_version"] = "lab_rule_review_v0_1"
    review.pop("approved")
    review.pop("hybrid_review")
    assert worker._review_is_safe(review) == "needs_review"


def test_missing_trusted_checksum_is_rejected(tmp_path, monkeypatch):
    values = _input(tmp_path)
    _prepare_private(values["private_root"], monkeypatch)
    values.pop("expected_sha")
    with pytest.raises(ValueError, match="checksum|manifest"):
        worker.run_worker(**values)


def test_wrong_trusted_checksum_is_rejected_before_pipeline(tmp_path, monkeypatch):
    values = _input(tmp_path)
    _prepare_private(values["private_root"], monkeypatch)
    values["expected_sha"] = "0" * 64
    values["processor"] = lambda *args: pytest.fail("pipeline must not run")
    with pytest.raises(ValueError, match="SHA256 mismatch"):
        worker.run_worker(**values)


def test_missing_manifest_is_rejected(tmp_path, monkeypatch):
    values = _input(tmp_path)
    _prepare_private(values["private_root"], monkeypatch)
    values.pop("expected_sha")
    values["manifest_path"] = tmp_path / "missing-manifest.json"
    with pytest.raises(FileNotFoundError):
        worker.run_worker(**values)


def test_manifest_outside_allowlisted_root_is_rejected(tmp_path, monkeypatch):
    values = _input(tmp_path)
    _prepare_private(values["private_root"], monkeypatch)
    values.pop("expected_sha")
    manifest_path = tmp_path / "outside.manifest.json"
    manifest_path.write_text("{}", encoding="utf-8")
    values["manifest_path"] = manifest_path
    with pytest.raises(ValueError, match="allowlisted root"):
        worker.run_worker(**values)


@pytest.mark.parametrize("run_id", ["../escape", ".", "..", "bad/id", ""])
def test_invalid_run_id_rejected(tmp_path, monkeypatch, run_id):
    values = _input(tmp_path)
    _prepare_private(values["private_root"], monkeypatch)
    values["run_id"] = run_id
    values["output_dir"] = values["private_root"] / "lab-runs" / run_id
    with pytest.raises(ValueError, match="run"):
        worker.run_worker(**values)


def test_pcap_outside_allowlisted_input_root_is_rejected(tmp_path, monkeypatch):
    values = _input(tmp_path)
    _prepare_private(values["private_root"], monkeypatch)
    outside = tmp_path / "outside.pcap"
    outside.write_bytes(b"synthetic-pcap")
    values["pcap"] = outside
    values["expected_sha"] = _sha256(outside)
    with pytest.raises(ValueError, match="allowlisted root"):
        worker.run_worker(**values)


def test_oversized_pcap_is_rejected_before_hashing(tmp_path, monkeypatch):
    values = _input(tmp_path)
    _prepare_private(values["private_root"], monkeypatch)
    monkeypatch.setattr(worker, "MAX_PCAP_SIZE_BYTES", 1)
    monkeypatch.setattr(
        worker,
        "sha256_file",
        lambda path: pytest.fail("size preflight must precede input hashing"),
    )
    with pytest.raises(ValueError, match="size limit"):
        worker.run_worker(**values)


def test_symlink_escape_is_rejected(tmp_path, monkeypatch):
    values = _input(tmp_path)
    _prepare_private(values["private_root"], monkeypatch)
    outside_root = tmp_path / "outside"
    outside_root.mkdir()
    outside = outside_root / "outside.pcap"
    outside.write_bytes(b"synthetic-pcap")
    link = values["input_root"] / "linked"
    try:
        link.symlink_to(outside_root, target_is_directory=True)
    except OSError:
        result = subprocess.run(
            ["cmd.exe", "/c", "mklink", "/J", str(link), str(outside_root)],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            pytest.skip("Windows symlink and junction creation are unavailable")
    try:
        values["pcap"] = link / outside.name
        values["expected_sha"] = _sha256(outside)
        with pytest.raises(ValueError, match="allowlisted root"):
            worker.run_worker(**values)
    finally:
        if link.exists():
            os.rmdir(link)


def test_insufficient_disk_is_rejected_before_pipeline(tmp_path, monkeypatch):
    values = _input(tmp_path)
    _prepare_private(values["private_root"], monkeypatch)
    monkeypatch.setattr(
        worker.shutil,
        "disk_usage",
        lambda _: SimpleNamespace(total=100, used=99, free=1),
    )
    monkeypatch.setattr(
        worker,
        "sha256_file",
        lambda path: pytest.fail("disk preflight must precede input hashing"),
    )
    values["processor"] = lambda *args: pytest.fail("pipeline must not run")
    with pytest.raises(OSError, match="disk space"):
        worker.run_worker(**values)


def test_missing_model_artifact_is_rejected(tmp_path, monkeypatch):
    values = _input(tmp_path)
    _prepare_private(values["private_root"], monkeypatch)
    (values["private_root"] / "lab-models" / "lab_syn_anomaly_v0_1" / "models.joblib").unlink()
    with pytest.raises(FileNotFoundError, match="models.joblib"):
        worker.run_worker(**values)


def test_missing_normal_reference_is_rejected(tmp_path, monkeypatch):
    values = _input(tmp_path)
    _prepare_private(values["private_root"], monkeypatch)
    reference = (
        values["private_root"]
        / "lab-sessions"
        / "normal-batch-v01"
        / "syn_windows_10s_normal-cal.csv"
    )
    reference.unlink()
    with pytest.raises(FileNotFoundError, match="normal-cal"):
        worker.run_worker(**values)


def test_review_model_checksum_must_match_preflight(tmp_path, monkeypatch):
    values = _input(tmp_path)
    _prepare_private(values["private_root"], monkeypatch)
    values["processor"] = _successful_processor(
        _valid_review(model_sha256="b" * 64)
    )
    with pytest.raises(worker.WorkerProcessingError, match="model checksum"):
        worker.run_worker(**values)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_pcap_sha256", "0" * 64),
        ("source_pcap_sha256", None),
        ("source_pcap_sha256", "malformed"),
        ("feature_csv_sha256", "0" * 64),
        ("feature_csv_sha256", None),
        ("feature_csv_sha256", "malformed"),
    ],
)
def test_review_provenance_must_match_input_and_feature_file(
    tmp_path, monkeypatch, field, value
):
    values = _input(tmp_path)
    _prepare_private(values["private_root"], monkeypatch)
    values["processor"] = _successful_processor(
        _valid_review(**{field: value})
    )

    with pytest.raises(worker.WorkerProcessingError, match="provenance"):
        worker.run_worker(**values)


@pytest.mark.parametrize(
    "field", ["source_pcap_sha256", "feature_csv_sha256"]
)
def test_review_provenance_fields_are_required(tmp_path, monkeypatch, field):
    values = _input(tmp_path)
    _prepare_private(values["private_root"], monkeypatch)
    review = _valid_review()
    review.pop(field)
    values["processor"] = _successful_processor(review)

    with pytest.raises(worker.WorkerProcessingError, match="provenance"):
        worker.run_worker(**values)


@pytest.mark.parametrize(
    ("override", "omitted"),
    [
        ({"input_sha256": "0" * 64}, ()),
        ({}, ("input_sha256",)),
        ({"input_sha256": "malformed"}, ()),
    ],
)
def test_prediction_feature_provenance_must_match(
    tmp_path, monkeypatch, override, omitted
):
    values = _input(tmp_path)
    _prepare_private(values["private_root"], monkeypatch)
    values["processor"] = _successful_processor(
        _valid_review(),
        prediction_overrides=override,
        omit_prediction_fields=omitted,
    )

    with pytest.raises(worker.WorkerProcessingError, match="provenance"):
        worker.run_worker(**values)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("training_performed", True),
        ("training_performed", "false"),
        ("suricata_rule_generated", True),
        ("suricata_rule_generated", 0),
        ("rule_deployed", True),
        ("rule_deployed", None),
    ],
)
def test_prediction_training_and_deployment_flags_must_be_false_booleans(
    tmp_path, monkeypatch, field, value
):
    values = _input(tmp_path)
    _prepare_private(values["private_root"], monkeypatch)
    values["processor"] = _successful_processor(
        _valid_review(),
        prediction_overrides={field: value},
    )

    with pytest.raises(worker.WorkerProcessingError, match="metadata"):
        worker.run_worker(**values)


@pytest.mark.parametrize(
    "field", ["training_performed", "suricata_rule_generated", "rule_deployed"]
)
def test_prediction_training_and_deployment_flags_are_required(
    tmp_path, monkeypatch, field
):
    values = _input(tmp_path)
    _prepare_private(values["private_root"], monkeypatch)
    values["processor"] = _successful_processor(
        _valid_review(),
        omit_prediction_fields=(field,),
    )

    with pytest.raises(worker.WorkerProcessingError, match="metadata"):
        worker.run_worker(**values)


def test_worker_accepts_complete_provenance_chain(tmp_path, monkeypatch):
    values = _input(tmp_path)
    _prepare_private(values["private_root"], monkeypatch)
    values["processor"] = _successful_processor(_valid_review())

    summary = worker.run_worker(**values)

    assert summary["status"] == "succeeded"
    assert _sha256(values["output_dir"] / "syn_windows.csv") == FEATURE_CSV_SHA256


def test_completed_run_verifier_checks_provenance_and_review_safety(tmp_path, monkeypatch):
    values = _input(tmp_path)
    _prepare_private(values["private_root"], monkeypatch)
    values["processor"] = _successful_processor(_valid_review())
    summary = worker.run_worker(**values)

    verified = worker.verify_completed_run(
        values["private_root"], values["run_id"], values["expected_sha"]
    )
    assert verified == summary

    review_path = values["output_dir"] / "review.json"
    review = json.loads(review_path.read_text(encoding="utf-8"))
    review["candidate_gate"]["rule_approval_authorized"] = True
    review_path.write_text(json.dumps(review), encoding="utf-8")
    with pytest.raises(worker.WorkerProcessingError, match="candidate_gate"):
        worker.verify_completed_run(
            values["private_root"], values["run_id"], values["expected_sha"]
        )

    review["candidate_gate"]["rule_approval_authorized"] = False
    review_path.write_text(json.dumps(review), encoding="utf-8")
    predictions_path = values["output_dir"] / "predictions.json"
    predictions = json.loads(predictions_path.read_text(encoding="utf-8"))
    predictions["input_sha256"] = "0" * 64
    predictions_path.write_text(json.dumps(predictions), encoding="utf-8")
    with pytest.raises(worker.WorkerProcessingError, match="provenance"):
        worker.verify_completed_run(
            values["private_root"], values["run_id"], values["expected_sha"]
        )


@pytest.mark.parametrize("predictions", [None, "{invalid json"])
def test_missing_or_malformed_predictions_fail_closed(
    tmp_path, monkeypatch, predictions
):
    values = _input(tmp_path)
    _prepare_private(values["private_root"], monkeypatch)

    def process(*args):
        output = values["output_dir"]
        output.mkdir(parents=True, exist_ok=False)
        (output / "syn_windows.csv").write_bytes(FEATURE_CSV.encode("utf-8"))
        (output / "review.json").write_text(
            json.dumps(_valid_review()), encoding="utf-8"
        )
        if predictions is not None:
            (output / "predictions.json").write_text(
                predictions, encoding="utf-8"
            )

    values["processor"] = process
    with pytest.raises(worker.WorkerProcessingError, match="prediction"):
        worker.run_worker(**values)


def test_validated_manifest_can_supply_trusted_checksum(tmp_path, monkeypatch):
    values = _input(tmp_path)
    _prepare_private(values["private_root"], monkeypatch)
    values.pop("expected_sha")
    manifest_path = values["input_root"] / "manifest.json"
    manifest_path.write_text(
        json.dumps({
            "schema_version": worker.WORKER_SCHEMA_VERSION,
            "pcap_sha256": _sha256(values["pcap"]),
            "source_ipv4": SRC,
            "destination_ipv4": DST,
            "run_id": "run-001",
            "capture_metadata": {},
        }),
        encoding="utf-8",
    )
    values["manifest_path"] = manifest_path
    values["processor"] = _successful_processor(_valid_review())
    summary = worker.run_worker(**values)
    assert summary["status"] == "succeeded"


def test_duplicate_processing_does_not_overwrite_run(tmp_path, monkeypatch):
    values = _input(tmp_path)
    _prepare_private(values["private_root"], monkeypatch)
    values["processor"] = _successful_processor(_valid_review())
    worker.run_worker(**values)
    previous = (values["output_dir"] / "worker_summary.json").read_bytes()
    with pytest.raises(FileExistsError):
        worker.run_worker(**values)
    assert (values["output_dir"] / "worker_summary.json").read_bytes() == previous


def _http_response(status, body=b'{"result":"created"}'):
    class Response:
        def __init__(self):
            self.status = status

        def read(self):
            return body

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

    return Response()


def _elasticsearch_summary(**overrides):
    summary = {
        "run_id": "run-001",
        "schema_version": worker.WORKER_SCHEMA_VERSION,
        "status": "succeeded",
        "review_status": "needs_review",
        "pcap_sha256": "a" * 64,
        "model_sha256": "b" * 64,
        "generated_at": "2026-11-10T00:00:00+00:00",
        "windows": 1,
        "isolation_forest_flagged": 0,
        "autoencoder_flagged": 0,
        "both_flagged": 0,
        "rule_generated_in_this_run": False,
        "deployable": False,
        "deployed": False,
    }
    summary.update(overrides)
    return summary


def test_elasticsearch_http_success_uses_stable_id_and_safe_document(monkeypatch):
    requests = []
    monkeypatch.setattr(
        worker.urllib.request,
        "urlopen",
        lambda request, timeout: (requests.append((request, timeout)) or _http_response(201)),
    )
    summary = _elasticsearch_summary(
        source_ipv4=SRC,
        destination_ipv4=DST,
        output_dir="C:\\private\\path",
        error="secret exception",
        generated_rule="private rule text",
    )
    first = worker.write_elasticsearch_summary(summary, "http://localhost:9200")
    second = worker.write_elasticsearch_summary(summary, "http://localhost:9200")
    assert first == second
    request, timeout = requests[0]
    assert "/suricata-ai-summary/_doc/" in request.full_url
    document = json.loads(request.data)
    serialized = json.dumps(document)
    for sensitive in (SRC, DST, "private", "secret exception", "C:\\\\"):
        assert sensitive not in serialized
    assert timeout > 0


def test_safe_summary_preserves_validated_hybrid_classification():
    summary = _elasticsearch_summary(
        hybrid_classification="reconnaissance_consistent"
    )

    safe = worker._safe_summary_fields(summary)

    assert safe["hybrid_classification"] == "reconnaissance_consistent"


def test_safe_summary_rejects_unknown_hybrid_classification():
    with pytest.raises(ValueError, match="hybrid_classification"):
        worker._safe_summary_fields(
            _elasticsearch_summary(hybrid_classification="made_up")
        )


def test_safe_summary_accepts_explicit_false_approval():
    safe = worker._safe_summary_fields(_elasticsearch_summary(approved=False))

    assert safe["approved"] is False


@pytest.mark.parametrize("value", [True, 0, "false", None])
def test_safe_summary_rejects_non_false_approval(value):
    with pytest.raises(ValueError, match="approved"):
        worker._safe_summary_fields(_elasticsearch_summary(approved=value))


def test_safe_summary_keeps_historical_document_without_approval():
    safe = worker._safe_summary_fields(_elasticsearch_summary())

    assert "approved" not in safe


def test_hybrid_classification_mismatch_is_rejected():
    with pytest.raises(ValueError, match="do not match"):
        worker.validate_hybrid_classification_match(
            _elasticsearch_summary(
                hybrid_classification="reconnaissance_consistent"
            ),
            {"hybrid_review": {"classification": "anomalous_not_reconnaissance"}},
        )


def test_elasticsearch_rejects_non_boolean_rule_generation_metadata(monkeypatch):
    monkeypatch.setattr(
        worker.urllib.request,
        "urlopen",
        lambda request, timeout: _http_response(201),
    )
    with pytest.raises(ValueError, match="rule_generated_in_this_run"):
        worker.write_elasticsearch_summary(
            _elasticsearch_summary(rule_generated_in_this_run="private rule text"),
            "http://localhost:9200",
        )


def test_elasticsearch_connection_failure_is_explicit(monkeypatch):
    def fail(*args, **kwargs):
        raise urllib.error.URLError("unavailable")
    monkeypatch.setattr(worker.urllib.request, "urlopen", fail)
    with pytest.raises(worker.ElasticsearchConnectionError):
        worker.write_elasticsearch_summary(
            _elasticsearch_summary(),
            "http://localhost:9200",
        )


def test_elasticsearch_conflict_is_accepted_only_after_exact_get(monkeypatch):
    summary = _elasticsearch_summary()
    safe_document = worker._safe_summary_fields(summary)
    document_id = hashlib.sha256(b"run-001").hexdigest()
    requests = []

    def conflict_then_get(request, timeout):
        requests.append(request)
        if request.method == "PUT":
            raise urllib.error.HTTPError(
                request.full_url, 409, "conflict", {}, None
            )
        return _http_response(200, json.dumps({
            "_id": document_id,
            "_index": worker.DEFAULT_ES_INDEX,
            "found": True,
            "_source": safe_document,
        }).encode("utf-8"))

    monkeypatch.setattr(worker.urllib.request, "urlopen", conflict_then_get)
    result = worker.write_elasticsearch_summary(summary, "http://localhost:9200")
    assert result["status"] == "already_exists"
    assert len(requests) == 2
    assert requests[1].method == "GET"
    assert document_id in requests[1].full_url


@pytest.mark.parametrize(
    "document",
    [
        {"found": False},
        {"found": True, "_id": "different", "_source": {}},
        {
            "found": True,
            "_id": hashlib.sha256(b"run-001").hexdigest(),
            "_index": worker.DEFAULT_ES_INDEX,
            "_source": {"status": "failed"},
        },
    ],
)
def test_elasticsearch_conflict_rejects_missing_or_mismatched_get(
    monkeypatch, document
):
    def conflict_then_get(request, timeout):
        if request.method == "PUT":
            raise urllib.error.HTTPError(
                request.full_url, 409, "conflict", {}, None
            )
        return _http_response(200, json.dumps(document).encode("utf-8"))

    monkeypatch.setattr(worker.urllib.request, "urlopen", conflict_then_get)
    with pytest.raises(worker.ElasticsearchConflictError):
        worker.write_elasticsearch_summary(
            _elasticsearch_summary(),
            "http://localhost:9200",
        )


def test_elasticsearch_conflict_get_failure_is_not_success(monkeypatch):
    error = urllib.error.HTTPError(
        "http://localhost", 409, "conflict", {}, None
    )
    def conflict_then_failed_get(request, timeout):
        if request.method == "PUT":
            raise error
        raise urllib.error.URLError("unavailable")

    monkeypatch.setattr(
        worker.urllib.request,
        "urlopen",
        conflict_then_failed_get,
    )
    with pytest.raises(worker.ElasticsearchConnectionError):
        worker.write_elasticsearch_summary(
            _elasticsearch_summary(),
            "http://localhost:9200",
        )


def test_elasticsearch_conflict_rejects_boolean_for_numeric_summary_field(
    monkeypatch,
):
    summary = _elasticsearch_summary()
    existing_source = worker._safe_summary_fields(summary)
    existing_source["windows"] = True
    document_id = hashlib.sha256(b"run-001").hexdigest()

    def conflict_then_get(request, timeout):
        if request.method == "PUT":
            raise urllib.error.HTTPError(
                request.full_url, 409, "conflict", {}, None
            )
        return _http_response(200, json.dumps({
            "_id": document_id,
            "_index": worker.DEFAULT_ES_INDEX,
            "found": True,
            "_source": existing_source,
        }).encode("utf-8"))

    monkeypatch.setattr(worker.urllib.request, "urlopen", conflict_then_get)
    with pytest.raises(worker.ElasticsearchConflictError):
        worker.write_elasticsearch_summary(summary, "http://localhost:9200")


def test_elasticsearch_server_error_is_explicit(monkeypatch):
    error = urllib.error.HTTPError(
        "http://localhost", 500, "server error", {}, None
    )
    monkeypatch.setattr(
        worker.urllib.request,
        "urlopen",
        lambda *args, **kwargs: (_ for _ in ()).throw(error),
    )
    with pytest.raises(worker.ElasticsearchWriteError, match="HTTP 500"):
        worker.write_elasticsearch_summary(
            _elasticsearch_summary(),
            "http://localhost:9200",
        )


def test_historical_review_statuses_remain_lowercase():
    assert worker.normalize_review_status("needs_review") == "needs_review"
    assert worker.normalize_review_status("NEEDS_REVIEW") == "needs_review"
    assert (
        worker.normalize_review_status("REJECTED_KNOWN_FALSE_POSITIVE")
        == "rejected_known_false_positive"
    )
