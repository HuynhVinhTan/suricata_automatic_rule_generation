"""High-resolution academic plots for latency aggregation outputs."""

from __future__ import annotations

import csv
import json
from pathlib import Path


def _read_csv(path: Path) -> list[dict]:
    with path.open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream))


def _save(figure, output: Path, stem: str) -> list[str]:
    png = output / f"{stem}.png"
    svg = output / f"{stem}.svg"
    figure.savefig(png, dpi=300, facecolor="white", bbox_inches="tight")
    figure.savefig(svg, facecolor="white", bbox_inches="tight")
    return [str(png), str(svg)]


def plot_latency_figures(
    per_run_path: str | Path,
    summary_path: str | Path,
    coverage_path: str | Path,
    output_dir: str | Path,
) -> dict:
    """Plot only measured observations; missing empirical groups stay pending."""
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    per_run = _read_csv(Path(per_run_path))
    summary = _read_csv(Path(summary_path))
    coverage = json.loads(Path(coverage_path).read_text(encoding="utf-8"))
    measured = [row for row in per_run if row.get("validity") == "measured" and row.get("elapsed_ms") not in (None, "")]
    pending: list[dict] = []
    generated: list[str] = []
    if not measured:
        pending.extend([
            {"figure": "H17", "reason": "no measured empirical latency observations"},
            {"figure": "H18", "reason": "no measured empirical latency observations"},
        ])
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        pending.append({"figure": "all", "reason": "matplotlib is unavailable"})
        plt = None

    if measured and plt is not None:
        plt.rcParams.update({
            "figure.facecolor": "white",
            "axes.facecolor": "white",
            "font.size": 10,
            "axes.titlesize": 13,
            "axes.labelsize": 11,
        })
        available_summary = [row for row in summary if row.get("valid_observations", "0") not in ("", "0")]
        if available_summary:
            labels = [row["stage"] for row in available_summary]
            means = [float(row["mean_ms"]) for row in available_summary]
            p95 = [float(row["p95_ms"]) for row in available_summary]
            figure, axis = plt.subplots(figsize=(11, 6))
            positions = list(range(len(labels)))
            axis.bar(positions, means, color="#2563eb", label="Trung bình")
            axis.scatter(positions, p95, color="#dc2626", marker="D", label="P95", zorder=3)
            axis.set_xticks(positions, labels, rotation=35, ha="right")
            axis.set_ylabel("Thời gian (ms)")
            axis.set_title("H17 — Phân rã độ trễ theo giai đoạn")
            axis.legend()
            axis.grid(axis="y", alpha=0.25)
            figure.tight_layout()
            generated.extend(_save(figure, output, "H17_latency_stage_breakdown"))
            plt.close(figure)
        else:
            pending.append({"figure": "H17_stage_breakdown", "reason": "no complete stage summary"})

        run_values: dict[str, list[float]] = {}
        for row in measured:
            run_values.setdefault(row["run_id"], []).append(float(row["elapsed_ms"]))
        if run_values:
            figure, axis = plt.subplots(figsize=(9, 5))
            labels = list(run_values)
            axis.bar(labels, [sum(values) for values in run_values.values()], color="#0f766e")
            axis.set_ylabel("Tổng thời gian quan sát (ms)")
            axis.set_title("H18 — Độ trễ theo phiên đo")
            axis.tick_params(axis="x", rotation=35)
            axis.grid(axis="y", alpha=0.25)
            figure.tight_layout()
            generated.extend(_save(figure, output, "H18_latency_per_session"))
            plt.close(figure)

        labels = {row.get("label", "").upper() for row in measured}
        if {"NORMAL", "ATTACK"} <= labels:
            grouped = {
                label: [float(row["elapsed_ms"]) for row in measured if row.get("label", "").upper() == label]
                for label in ("NORMAL", "ATTACK")
            }
            figure, axis = plt.subplots(figsize=(7, 5))
            axis.boxplot([grouped["NORMAL"], grouped["ATTACK"]], labels=["Normal", "Attack"], showmeans=True)
            axis.set_ylabel("Thời gian (ms)")
            axis.set_title("H18 — So sánh độ trễ Normal và Attack")
            axis.grid(axis="y", alpha=0.25)
            figure.tight_layout()
            generated.extend(_save(figure, output, "H18_normal_attack_latency"))
            plt.close(figure)
        else:
            pending.append({"figure": "H18_normal_attack", "reason": "both Normal and Attack labels are not present in verified evidence"})

        if not coverage.get("complete_sequential_measurements", False):
            pending.append({"figure": "H17_waterfall", "reason": "complete sequential T0-T11 measurements are not verified"})

    pending_doc = {
        "schema_version": "latency_figures_status_v1",
        "status": "READY" if generated else "PENDING",
        "generated": generated,
        "pending": pending,
        "synthetic_data_used": False,
    }
    (output / "figures_pending.json").write_text(json.dumps(pending_doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return {"status": pending_doc["status"], "generated": generated, "pending": pending}
