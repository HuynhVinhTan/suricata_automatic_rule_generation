import json

from netids.eve_worker import JsonlEveReader, StreamingInferenceWorker
from netids.lab_workflow import run_streaming_lab_workflow

from test_eve_worker import flow_event, real_model_adapter


def test_lab_workflow_records_runtime_gates_without_claiming_activation(tmp_path):
    eve = tmp_path / "eve.json"
    output = tmp_path / "anomalies.jsonl"
    evidence = tmp_path / "workflow.json"
    eve.write_text(json.dumps(flow_event()) + "\n", encoding="utf-8")
    worker = StreamingInferenceWorker(
        reader=JsonlEveReader(eve),
        model=real_model_adapter(),
        output_path=output,
        run_id="workflow-test",
    )

    report = run_streaming_lab_workflow(worker, evidence)

    assert report["overall_status"] == "BLOCKED"
    assert report["stages"]["continuous_ingestion"]["status"] == "TESTED"
    assert report["stages"]["continuous_inference"]["status"] == "TESTED"
    assert report["stages"]["continuous_inference"]["processed_events"] == 1
    assert report["stages"]["isolated_activation"]["status"] == "BLOCKED"
    assert report["stages"]["rollback"]["status"] == "BLOCKED"
    assert report["latency"]["schema_version"] == "latency_trace_v1"
    assert json.loads(evidence.read_text(encoding="utf-8"))["run_id"] == "workflow-test"
