"""
Training script for the Network Anomaly Detection model.

SAFETY NOTICE: Trains on authorized telemetry data only. Does not generate
scanning tools or real attack traffic signatures.
"""

from typing import Optional

import numpy as np
import pandas as pd
from sklearn.metrics import classification_report

from ..common.io import load_dataframe, save_model
from ..common.logger import get_logger
from ..common.metrics import compute_classification_metrics, print_metrics
from ..common.utils import ensure_dirs, get_reports_dir, load_config, save_json
from ..data_generation.network_synth import generate_network_data
from ..models.network_model import build_network_supervised_pipeline, build_network_unsupervised_pipeline
from ..models.registry import LABEL_REGISTRY, MODEL_REGISTRY
from ..preprocessing.encoders import encode_labels, get_feature_lists
from ..preprocessing.feature_builder import handle_missing, prepare_xy, split_data

logger = get_logger(__name__)


def train_network(
    df: Optional[pd.DataFrame] = None,
    save: bool = True,
    verbose: bool = True,
) -> dict:
    """Train network anomaly detection models (both unsupervised and supervised)."""
    ensure_dirs()
    config = load_config()
    seed = config["global"]["random_seed"]

    if df is None:
        try:
            df = load_dataframe("network_synthetic")
        except FileNotFoundError:
            logger.info("Synthetic data not found, generating now...")
            df = generate_network_data(seed=seed)

    numeric_cols, binary_cols, categorical_cols = get_feature_lists("network")
    df = handle_missing(df, numeric_cols, categorical_cols)
    all_feature_cols = numeric_cols + binary_cols + categorical_cols

    X, y_str = prepare_xy(df, all_feature_cols)

    X_train, X_test, y_train_str, y_test_str = split_data(X, y_str, seed=seed)

    logger.info("Training IsolationForest (unsupervised)...")
    X_normal = X_train[y_train_str == "normal"]
    iso_pipeline = build_network_unsupervised_pipeline()
    iso_pipeline.fit(X_normal)

    iso_raw = iso_pipeline.predict(X_test)
    iso_pred = np.where(iso_raw == -1, "anomalous", "normal")

    iso_report = classification_report(y_test_str, iso_pred, output_dict=True, zero_division=0)
    logger.info("IsolationForest Classification Report:")
    logger.info(f"\n{classification_report(y_test_str, iso_pred, zero_division=0)}")

    logger.info("Training Supervised Network Classifier (RandomForest)...")
    y_enc, le = encode_labels(y_train_str)
    y_test_enc, _ = encode_labels(y_test_str)
    le.fit(y_str)
    y_train_enc = le.transform(y_train_str)
    y_test_enc = le.transform(y_test_str)

    sup_pipeline = build_network_supervised_pipeline()
    sup_pipeline.fit(X_train, y_train_enc)
    y_pred_sup = sup_pipeline.predict(X_test)
    sup_metrics = compute_classification_metrics(y_test_enc, y_pred_sup, le.classes_.tolist())
    print_metrics(sup_metrics, "Network Supervised RF")

    if save:
        save_model(iso_pipeline, MODEL_REGISTRY["network_unsupervised"])
        save_model(sup_pipeline, MODEL_REGISTRY["network_supervised"])
        save_model(le, LABEL_REGISTRY["network_supervised"])

        report = {
            "model": "network_anomaly",
            "unsupervised_report": iso_report,
            "supervised_metrics": sup_metrics,
            "label_classes": le.classes_.tolist(),
            "n_train": len(X_train),
            "n_test": len(X_test),
        }
        save_json(report, get_reports_dir() / "network_training_report.json")
        logger.info("Network model artifacts and report saved.")

    return sup_metrics
