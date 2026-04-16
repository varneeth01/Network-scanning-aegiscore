"""Evaluation metrics utilities for AegisCore."""

from typing import Any, Dict, List

import numpy as np
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from .logger import get_logger

logger = get_logger(__name__)


def compute_classification_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    labels: List[str],
    y_proba: np.ndarray = None,
) -> Dict[str, Any]:
    """Compute classification metrics and return a summary dict."""
    report = classification_report(y_true, y_pred, target_names=labels, output_dict=True, zero_division=0)
    cm = confusion_matrix(y_true, y_pred).tolist()

    metrics: Dict[str, Any] = {
        "classification_report": report,
        "confusion_matrix": cm,
        "f1_macro": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "precision_macro": float(precision_score(y_true, y_pred, average="macro", zero_division=0)),
        "recall_macro": float(recall_score(y_true, y_pred, average="macro", zero_division=0)),
    }

    if y_proba is not None and len(np.unique(y_true)) == 2:
        try:
            metrics["roc_auc"] = float(roc_auc_score(y_true, y_proba[:, 1]))
        except Exception:
            pass

    return metrics


def print_metrics(metrics: Dict[str, Any], model_name: str) -> None:
    """Pretty print metrics summary."""
    logger.info(f"=== {model_name} Evaluation Metrics ===")
    logger.info(f"F1 Macro: {metrics.get('f1_macro', 'N/A'):.4f}")
    logger.info(f"Precision Macro: {metrics.get('precision_macro', 'N/A'):.4f}")
    logger.info(f"Recall Macro: {metrics.get('recall_macro', 'N/A'):.4f}")
    if "roc_auc" in metrics:
        logger.info(f"ROC AUC: {metrics['roc_auc']:.4f}")
