"""
Training script for the Honeypot Attack Classifier.

SAFETY NOTICE: Trains a defensive classifier on synthetic or owner-provided
honeypot telemetry data. Does not generate attack payloads or offensive tools.
"""

from pathlib import Path
from typing import Optional

import pandas as pd

from ..common.io import load_dataframe, save_model
from ..common.logger import get_logger
from ..common.metrics import compute_classification_metrics, print_metrics
from ..common.utils import ensure_dirs, get_reports_dir, load_config, save_json, versioned_model_name
from ..data_generation.honeypot_synth import LABELS, generate_honeypot_data
from ..models.honeypot_model import build_honeypot_baseline, build_honeypot_pipeline
from ..models.registry import LABEL_REGISTRY, MODEL_REGISTRY
from ..preprocessing.encoders import encode_labels, get_feature_lists
from ..preprocessing.feature_builder import handle_missing, prepare_xy, split_data

logger = get_logger(__name__)


def train_honeypot(
    df: Optional[pd.DataFrame] = None,
    save: bool = True,
    verbose: bool = True,
) -> dict:
    """Train the Honeypot Classifier. Returns a dict of metrics."""
    ensure_dirs()
    config = load_config()
    seed = config["global"]["random_seed"]

    if df is None:
        try:
            df = load_dataframe("honeypot_synthetic")
        except FileNotFoundError:
            logger.info("Synthetic data not found, generating now...")
            df = generate_honeypot_data(seed=seed)

    numeric_cols, binary_cols, categorical_cols = get_feature_lists("honeypot")
    df = handle_missing(df, numeric_cols, categorical_cols)

    all_feature_cols = numeric_cols + binary_cols + categorical_cols
    X, y = prepare_xy(df, all_feature_cols)

    X_train, X_test, y_train_str, y_test_str = split_data(X, y, seed=seed)

    from sklearn.preprocessing import LabelEncoder
    le = LabelEncoder()
    le.fit(y_train_str)
    y_train = pd.Series(le.transform(y_train_str))
    unseen = set(y_test_str.unique()) - set(le.classes_)
    if unseen:
        y_test_str = y_test_str[y_test_str.isin(le.classes_)]
        X_test = X_test.loc[y_test_str.index]
    y_test = pd.Series(le.transform(y_test_str))

    logger.info("Training Honeypot Baseline (RandomForest)...")
    baseline = build_honeypot_baseline()
    baseline.fit(X_train, y_train)
    y_pred_base = baseline.predict(X_test)
    base_metrics = compute_classification_metrics(y_test.values, y_pred_base, le.classes_.tolist())
    print_metrics(base_metrics, "Honeypot Baseline")

    logger.info("Training Honeypot Classifier (XGBoost/GBT)...")
    pipeline = build_honeypot_pipeline()
    pipeline.fit(X_train, y_train)
    y_pred = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)
    metrics = compute_classification_metrics(y_test.values, y_pred, le.classes_.tolist(), y_proba)
    print_metrics(metrics, "Honeypot XGBoost")

    if save:
        save_model(pipeline, MODEL_REGISTRY["honeypot"])
        save_model(baseline, MODEL_REGISTRY["honeypot_baseline"])
        save_model(le, LABEL_REGISTRY["honeypot"])

        report = {
            "model": "honeypot",
            "baseline_metrics": base_metrics,
            "improved_metrics": metrics,
            "label_classes": le.classes_.tolist(),
            "n_train": len(X_train),
            "n_test": len(X_test),
        }
        save_json(report, get_reports_dir() / "honeypot_training_report.json")
        logger.info("Honeypot model artifacts and report saved.")

    return metrics
