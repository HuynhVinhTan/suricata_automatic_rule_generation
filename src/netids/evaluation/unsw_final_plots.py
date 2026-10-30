"""Official test figures from frozen model predictions."""

from pathlib import Path

import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np

from sklearn.metrics import (
    ConfusionMatrixDisplay,
    average_precision_score,
    precision_recall_curve,
)


def save_final_figures(folder, labels, scores, thresholds):
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=False)

    names = []

    fig, ax = plt.subplots(figsize=(8, 5))

    for family, values in scores.items():
        precision, recall, _ = precision_recall_curve(
            labels, values
        )
        ap = average_precision_score(labels, values)

        ax.plot(
            recall, precision,
            label=f"{family} (AP={ap:.3f})"
        )

    ax.axhline(
        float(np.mean(labels)),
        linestyle="--",
        label="Attack prevalence",
    )

    ax.set(
        xlabel="Recall",
        ylabel="Precision",
        xlim=(0, 1),
        ylim=(0, 1.02),
        title="UNSW-NB15 Official Test - PR Curves",
    )

    ax.legend()
    fig.tight_layout()

    name = "01_pr_official_test.png"
    fig.savefig(folder / name, dpi=180)
    plt.close(fig)
    names.append(name)

    fig, ax = plt.subplots(figsize=(6, 5))

    rf_pred = (
        scores["RF"] >= thresholds["RF"]
    ).astype(int)

    ConfusionMatrixDisplay.from_predictions(
        labels,
        rf_pred,
        labels=[0, 1],
        display_labels=["Normal", "Attack"],
        values_format="d",
        cmap="Blues",
        ax=ax,
    )

    ax.set_title(
        "Frozen Random Forest - Official Test"
    )

    fig.tight_layout()

    name = "02_rf_confusion_official_test.png"
    fig.savefig(folder / name, dpi=180)
    plt.close(fig)
    names.append(name)

    families = list(scores)
    recall_values = []
    fpr_values = []

    for family in families:
        pred = (
            scores[family] >= thresholds[family]
        )

        recall_values.append(
            float(np.mean(pred[labels == 1]))
        )

        fpr_values.append(
            float(np.mean(pred[labels == 0]))
        )

    fig, ax = plt.subplots(figsize=(8, 5))
    x = np.arange(len(families))

    ax.bar(
        x - 0.19,
        recall_values,
        0.38,
        label="Recall",
    )

    ax.bar(
        x + 0.19,
        fpr_values,
        0.38,
        label="FPR",
    )

    ax.set_xticks(x)
    ax.set_xticklabels(families)

    ax.set(
        ylim=(0, 1),
        ylabel="Fraction",
        title="Official Test - Recall and FPR",
    )

    ax.legend()
    fig.tight_layout()

    name = "03_recall_fpr_official_test.png"
    fig.savefig(folder / name, dpi=180)
    plt.close(fig)
    names.append(name)

    return names