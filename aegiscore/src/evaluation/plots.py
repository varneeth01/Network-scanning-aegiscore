"""
Evaluation plots for AegisCore model reports.

Generates confusion matrices and feature importance bar charts.
"""

from pathlib import Path
from typing import Any, Dict, List

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from ..common.logger import get_logger
from ..common.utils import get_reports_dir

logger = get_logger(__name__)


def plot_confusion_matrix(
    cm: List[List[int]],
    labels: List[str],
    model_name: str,
    output_dir: Path = None,
) -> Path:
    """Plot and save a confusion matrix."""
    output_dir = output_dir or get_reports_dir()
    output_dir.mkdir(parents=True, exist_ok=True)

    cm_array = np.array(cm)
    fig, ax = plt.subplots(figsize=(max(6, len(labels)), max(5, len(labels))))
    im = ax.imshow(cm_array, interpolation="nearest", cmap=plt.cm.Blues)
    fig.colorbar(im)
    ax.set(
        xticks=np.arange(len(labels)),
        yticks=np.arange(len(labels)),
        xticklabels=labels,
        yticklabels=labels,
        ylabel="True label",
        xlabel="Predicted label",
        title=f"{model_name} Confusion Matrix",
    )
    plt.setp(ax.get_xticklabels(), rotation=45, ha="right", rotation_mode="anchor")

    thresh = cm_array.max() / 2.0
    for i in range(len(labels)):
        for j in range(len(labels)):
            ax.text(j, i, str(cm_array[i, j]),
                    ha="center", va="center",
                    color="white" if cm_array[i, j] > thresh else "black")

    fig.tight_layout()
    path = output_dir / f"{model_name}_confusion_matrix.png"
    plt.savefig(path, dpi=100, bbox_inches="tight")
    plt.close(fig)
    logger.info(f"Saved confusion matrix: {path}")
    return path


def plot_feature_importance(
    feature_names: List[str],
    importances: List[float],
    model_name: str,
    top_n: int = 15,
    output_dir: Path = None,
) -> Path:
    """Plot and save a horizontal bar chart of feature importances."""
    output_dir = output_dir or get_reports_dir()
    output_dir.mkdir(parents=True, exist_ok=True)

    pairs = sorted(zip(feature_names, importances), key=lambda x: x[1], reverse=True)[:top_n]
    names, vals = zip(*pairs) if pairs else ([], [])

    fig, ax = plt.subplots(figsize=(9, max(4, top_n // 2)))
    ax.barh(list(names)[::-1], list(vals)[::-1], color="steelblue")
    ax.set_xlabel("Importance")
    ax.set_title(f"{model_name} — Top {top_n} Features")
    fig.tight_layout()
    path = output_dir / f"{model_name}_feature_importance.png"
    plt.savefig(path, dpi=100, bbox_inches="tight")
    plt.close(fig)
    logger.info(f"Saved feature importance plot: {path}")
    return path
