"""
Training script for the Security Misconfiguration / Exposure Risk model.

SAFETY NOTICE: Trains on authorized configuration data. Does not generate
exploit code or provide instructions for bypassing security controls.
"""

from typing import Optional

import pandas as pd

from ..common.io import load_dataframe, save_model
from ..common.logger import get_logger
from ..common.metrics import compute_classification_metrics, print_metrics
from ..common.utils import ensure_dirs, get_reports_dir, load_config, save_json
from ..data_generation.posture_synth import generate_posture_data
from ..models.posture_model import build_posture_baseline, build_posture_pipeline
from ..models.registry import LABEL_REGISTRY, MODEL_REGISTRY
from ..preprocessing.encoders import encode_labels, get_feature_lists
from ..preprocessing.feature_builder import handle_missing, prepare_xy, split_data

logger = get_logger(__name__)

POSTURE_FEATURE_COLS = [
    "missing_hsts", "missing_csp", "missing_x_content_type_options",
    "insecure_cookie_flags", "weak_tls", "deprecated_protocol_present",
    "admin_interface_exposed", "risky_management_port_exposed",
    "open_port_count", "legacy_service_count", "dependency_vuln_count",
    "secrets_detected", "public_bucket_like_flag", "authz_gap_indicator",
    "excessive_cors_flag", "debug_banner_present", "default_credentials_risk",
    "segmentation_risk_score",
]


def train_posture(
    df: Optional[pd.DataFrame] = None,
    save: bool = True,
    verbose: bool = True,
) -> dict:
    """Train the Security Posture Risk Classifier. Returns a dict of metrics."""
    ensure_dirs()
    config = load_config()
    seed = config["global"]["random_seed"]

    if df is None:
        try:
            df = load_dataframe("posture_synthetic")
        except FileNotFoundError:
            logger.info("Synthetic data not found, generating now...")
            df = generate_posture_data(seed=seed)

    numeric_cols, binary_cols, categorical_cols = get_feature_lists("posture")
    df = handle_missing(df, numeric_cols, [])

    X, y = prepare_xy(df, POSTURE_FEATURE_COLS)

    X_train, X_test, y_train_str, y_test_str = split_data(X, y, seed=seed)

    from sklearn.preprocessing import LabelEncoder
    le = LabelEncoder()
    le.fit(y_train_str)
    y_train = pd.Series(le.transform(y_train_str))
    all_test_classes = set(y_test_str.unique()) - set(le.classes_)
    if all_test_classes:
        y_test_str = y_test_str[y_test_str.isin(le.classes_)]
        X_test = X_test.loc[y_test_str.index]
    y_test = pd.Series(le.transform(y_test_str))

    logger.info("Training Posture Baseline (RandomForest)...")
    baseline = build_posture_baseline()
    baseline.fit(X_train, y_train)
    y_pred_base = baseline.predict(X_test)
    base_metrics = compute_classification_metrics(y_test.values, y_pred_base, le.classes_.tolist())
    print_metrics(base_metrics, "Posture Baseline")

    logger.info("Training Posture Risk Classifier (XGBoost/GBT)...")
    pipeline = build_posture_pipeline()
    pipeline.fit(X_train, y_train)
    y_pred = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)
    metrics = compute_classification_metrics(y_test.values, y_pred, le.classes_.tolist(), y_proba)
    print_metrics(metrics, "Posture XGBoost")

    if save:
        save_model(pipeline, MODEL_REGISTRY["posture"])
        save_model(baseline, MODEL_REGISTRY["posture_baseline"])
        save_model(le, LABEL_REGISTRY["posture"])

        report = {
            "model": "posture_risk",
            "baseline_metrics": base_metrics,
            "improved_metrics": metrics,
            "label_classes": le.classes_.tolist(),
            "n_train": len(X_train),
            "n_test": len(X_test),
        }
        save_json(report, get_reports_dir() / "posture_training_report.json")
        logger.info("Posture model artifacts and report saved.")

    return metrics
