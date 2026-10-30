"""Reproducible plots from actual model predictions."""

from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    precision_recall_curve,
)


def save_development_figures(results, y_true, output_dir):
    """Generate development-only figures, never fabricated scores."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=False)

    fig, ax = plt.subplots(figsize=(8, 5))
    prevalence = float(np.mean(y_true))

    for item in results:
        precision, recall, _ = precision_recall_curve(
            y_true, item["scores"]
        )
        ax.plot(
            recall,
            precision,
            label=f'{item["name"]} (AP={item["ap"]:.3f})',
        )

    ax.axhline(
        prevalence,
        linestyle="--",
        color="gray",
        label=f"Positive prevalence={prevalence:.3f}",
    )
    ax.set(
        xlabel="Recall",
        ylabel="Precision",
        title="UNSW-NB15 - Development Validation PR Curves",
        xlim=(0, 1),
        ylim=(0, 1.02),
    )
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(output_dir / "01_pr_curves_validation.png", dpi=180)
    plt.close(fig)

    names = [item["name"] for item in results]
    f1_values = [item["f1"] for item in results]

    fig, ax = plt.subplots(figsize=(9, 5))
    ax.barh(names, f1_values)
    ax.set(
        xlabel="F1 at provisional threshold 0.5",
        xlim=(0, 1),
        title="UNSW-NB15 - ML Development Comparison",
    )
    fig.tight_layout()
    fig.savefig(output_dir / "02_f1_comparison_validation.png", dpi=180)
    plt.close(fig)

    selected = max(results, key=lambda item: item["ap"])
    predictions = (selected["scores"] >= 0.5).astype(int)

    fig, ax = plt.subplots(figsize=(6, 5))
    ConfusionMatrixDisplay.from_predictions(
        y_true,
        predictions,
        labels=[0, 1],
        display_labels=["Normal", "Attack"],
        cmap="Blues",
        values_format="d",
        ax=ax,
    )
    ax.set_title(
        f'{selected["name"]} - Development Validation Only'
    )
    fig.tight_layout()
    fig.savefig(
        output_dir / "03_confusion_matrix_validation.png",
        dpi=180,
    )
    plt.close(fig)

    return [
        "01_pr_curves_validation.png",
        "02_f1_comparison_validation.png",
        "03_confusion_matrix_validation.png",
    ]