"""Actual DL training and validation plots."""

from pathlib import Path

import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np

from sklearn.metrics import (
    average_precision_score,
    precision_recall_curve,
)


def save_dl_figures(directory, histories, y_true, mlp_score, ae_score):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)

    names = []

    for family, losses in histories.items():
        validation_key = (
            "val_loss" if family == "MLP" else "cal_loss"
        )

        if (
            "train_loss" not in losses
            or validation_key not in losses
            or not losses[validation_key]
        ):
            raise ValueError(
                "Missing actual training history: " + family
            )

        fig, ax = plt.subplots(figsize=(8, 5))

        ax.plot(
            range(1, len(losses["train_loss"]) + 1),
            losses["train_loss"],
            label="Training",
        )

        ax.plot(
            range(1, len(losses[validation_key]) + 1),
            losses[validation_key],
            label="Early-stopping validation",
        )

        ax.set(
            xlabel="Epoch",
            ylabel="Loss",
            title=f"UNSW {family} - Actual Training History",
        )
        ax.legend()
        fig.tight_layout()

        name = family.lower() + "_loss.png"
        fig.savefig(directory / name, dpi=180)
        plt.close(fig)
        names.append(name)

    fig, ax = plt.subplots(figsize=(8, 5))

    for scores, family in (
        (mlp_score, "MLP"),
        (ae_score, "Autoencoder"),
    ):
        precision, recall, _ = precision_recall_curve(
            y_true, scores
        )

        ap = average_precision_score(y_true, scores)

        ax.plot(
            recall,
            precision,
            label=f"{family} AP={ap:.4f}",
        )

    ax.set(
        xlabel="Recall",
        ylabel="Precision",
        title="UNSW DL - Development Validation PR Curves",
        xlim=(0, 1),
        ylim=(0, 1.02),
    )

    ax.legend()
    fig.tight_layout()

    name = "dl_pr_validation.png"
    fig.savefig(directory / name, dpi=180)
    plt.close(fig)
    names.append(name)

    fig, ax = plt.subplots(figsize=(8, 5))

    transformed = np.log1p(ae_score)

    ax.hist(
        transformed[y_true == 0],
        bins=45,
        alpha=0.6,
        label="Normal",
        density=True,
    )

    ax.hist(
        transformed[y_true == 1],
        bins=45,
        alpha=0.6,
        label="Attack",
        density=True,
    )

    ax.set(
        xlabel="log1p(AE Reconstruction Error)",
        ylabel="Density",
        title="UNSW AE - Validation Anomaly Scores",
    )

    ax.legend()
    fig.tight_layout()

    name = "ae_score_distribution_validation.png"
    fig.savefig(directory / name, dpi=180)
    plt.close(fig)
    names.append(name)

    return names