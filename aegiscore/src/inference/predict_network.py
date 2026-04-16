"""
Inference script for the Network Anomaly Detection model.

SAFETY NOTICE: Analyzes authorized network telemetry only. Does not
generate scanning tools or real attack traffic.
"""

from typing import Any, Dict

import numpy as np
import pandas as pd

from ..common.io import load_model
from ..common.logger import get_logger
from ..common.schemas import PredictionOutput, SEVERITY_MAP
from ..common.utils import get_synthetic_dir, risk_score_from_proba
from ..explainability.explanation_engine import build_explanation, build_reason_codes
from ..explainability.feature_importance import get_anomaly_contributions, get_top_features
from ..models.registry import LABEL_REGISTRY, MODEL_REGISTRY
from ..preprocessing.validators import validate_input, validated_to_df

logger = get_logger(__name__)

_NETWORK_NUMERIC_COLS = [
    "src_port", "dst_port", "bytes_sent", "bytes_received", "packets",
    "duration", "failed_connections", "distinct_destinations",
    "connection_frequency", "dns_query_volume", "tls_version_score",
    "beaconing_score", "hour_of_day",
]


def _get_network_baseline_stats() -> tuple:
    """Load or compute feature statistics for z-score anomaly explanation."""
    try:
        synthetic_path = get_synthetic_dir() / "network_synthetic.csv"
        if synthetic_path.exists():
            df = pd.read_csv(synthetic_path)
            normal_df = df[df["label"] == "normal"][_NETWORK_NUMERIC_COLS]
            return normal_df.mean(), normal_df.std().replace(0, 1)
    except Exception:
        pass
    default_means = pd.Series({col: 1.0 for col in _NETWORK_NUMERIC_COLS})
    default_stds = pd.Series({col: 1.0 for col in _NETWORK_NUMERIC_COLS})
    return default_means, default_stds


def predict_network(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run network anomaly detection on a single flow record.

    Uses supervised model primarily; falls back to unsupervised IsolationForest.

    Args:
        record: Dict matching NetworkInput schema.

    Returns:
        AegisCore standard prediction output dict.
    """
    validated = validate_input("network", record)
    df = validated_to_df(validated)

    try:
        pipeline = load_model(MODEL_REGISTRY["network_supervised"])
        le = load_model(LABEL_REGISTRY["network_supervised"])
        y_pred_enc = pipeline.predict(df)[0]
        y_proba = pipeline.predict_proba(df)[0]
        confidence = float(np.max(y_proba))
        prediction = le.inverse_transform([y_pred_enc])[0]
        top_feats = get_top_features(pipeline, df, top_n=5)
        reason_codes = build_reason_codes(top_feats, "network", record)
    except FileNotFoundError:
        logger.warning("Supervised model not found, using IsolationForest.")
        iso_pipeline = load_model(MODEL_REGISTRY["network_unsupervised"])
        raw = iso_pipeline.predict(df)[0]
        score_raw = iso_pipeline.score_samples(df)[0]
        prediction = "anomalous" if raw == -1 else "normal"
        confidence = float(1.0 - (score_raw + 0.5))
        confidence = max(0.0, min(1.0, confidence))

        means, stds = _get_network_baseline_stats()
        numeric_df = df[[c for c in _NETWORK_NUMERIC_COLS if c in df.columns]]
        top_feats = get_anomaly_contributions(numeric_df, means, stds, top_n=5)
        reason_codes = build_reason_codes(top_feats, "network", record)

    explanation = build_explanation(prediction, reason_codes, "network")

    beaconing = record.get("beaconing_score", 0.0)
    uncommon_port = record.get("uncommon_port_flag", 0)
    if beaconing >= 0.75 and uncommon_port:
        severity = "critical"
        rule_adjustments = ["RULE: Beaconing + uncommon port → critical severity"]
    elif prediction == "anomalous":
        severity = "high"
        rule_adjustments = []
    else:
        severity = SEVERITY_MAP.get(prediction, "info")
        rule_adjustments = []

    risk_score = risk_score_from_proba(confidence)

    output = PredictionOutput(
        model="network_anomaly_detector",
        prediction=prediction,
        confidence=round(confidence, 4),
        risk_score=risk_score,
        severity=severity,
        reason_codes=reason_codes,
        explanation=explanation,
        rule_adjustments=rule_adjustments if rule_adjustments else None,
    )
    return output.model_dump()


def predict_network_batch(records: list) -> list:
    return [predict_network(r) for r in records]
