import json

from netids.latency_figures import plot_latency_figures


def test_latency_figures_mark_missing_empirical_data_pending(tmp_path):
    per_run = tmp_path / "latency_per_run.csv"
    summary = tmp_path / "latency_stage_summary.csv"
    coverage = tmp_path / "latency_coverage.json"
    per_run.write_text(
        "run_id,stage,component,validity,elapsed_ms,label\n"
        "run-1,capture,capture,missing,,\n",
        encoding="utf-8",
    )
    summary.write_text(
        "stage,component,valid_observations,mean_ms,median_ms,p95_ms\n"
        "capture,capture,0,,,\n",
        encoding="utf-8",
    )
    coverage.write_text(json.dumps({"runs": {"run-1": {"missing_catalog_stages": ["capture"]}}}), encoding="utf-8")
    output = tmp_path / "figures"
    result = plot_latency_figures(per_run, summary, coverage, output)
    assert result["status"] == "PENDING"
    assert (output / "figures_pending.json").is_file()
    assert not list(output.glob("*.png"))
