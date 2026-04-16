"""
Evaluation report generator for AegisCore models.

Generates structured JSON and text reports for each model's training run.
"""

from pathlib import Path
from typing import Any, Dict

from ..common.logger import get_logger
from ..common.utils import get_reports_dir, load_json, save_json

logger = get_logger(__name__)


def print_classification_report(model_name: str) -> None:
    """Load and print a training report from the reports directory."""
    path = get_reports_dir() / f"{model_name}_training_report.json"
    if not path.exists():
        logger.warning(f"No report found at {path}. Train the model first.")
        return
    report = load_json(path)
    logger.info(f"\n=== {model_name.upper()} Training Report ===")
    improved = report.get("improved_metrics", {})
    logger.info(f"F1 Macro:        {improved.get('f1_macro', 'N/A'):.4f}")
    logger.info(f"Precision Macro: {improved.get('precision_macro', 'N/A'):.4f}")
    logger.info(f"Recall Macro:    {improved.get('recall_macro', 'N/A'):.4f}")
    logger.info(f"Train samples:   {report.get('n_train', 'N/A')}")
    logger.info(f"Test samples:    {report.get('n_test', 'N/A')}")
    logger.info(f"Classes:         {report.get('label_classes', [])}")


def summarize_all_reports() -> Dict[str, Any]:
    """Return a combined summary of all available training reports."""
    report_names = [
        "honeypot_training_report",
        "malware_training_report",
        "network_training_report",
        "posture_training_report",
    ]
    summary = {}
    for name in report_names:
        path = get_reports_dir() / f"{name}.json"
        if path.exists():
            report = load_json(path)
            improved = report.get("improved_metrics", {})
            summary[name] = {
                "f1_macro": improved.get("f1_macro"),
                "n_train": report.get("n_train"),
                "n_test": report.get("n_test"),
            }
    return summary
