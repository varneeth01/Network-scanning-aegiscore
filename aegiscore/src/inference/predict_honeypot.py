"""
Inference script for the Honeypot Attack Classifier.

SAFETY NOTICE: Analyzes honeypot telemetry defensively. Does not generate
attack payloads or assist with offensive operations.
"""

import json
from typing import Any, Dict

import numpy as np
import pandas as pd

from ..common.io import load_model
from ..common.logger import get_logger
from ..common.schemas import PredictionOutput, SEVERITY_MAP
from ..common.utils import risk_score_from_proba
from ..explainability.explanation_engine import build_explanation, build_reason_codes
from ..explainability.feature_importance import get_top_features
from ..models.registry import LABEL_REGISTRY, MODEL_REGISTRY
from ..preprocessing.validators import validate_input, validated_to_df
from ..rules.honeypot_rules import apply_honeypot_rules

logger = get_logger(__name__)


def predict_honeypot(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run inference on a single honeypot event record.

    Args:
        record: Dict matching HoneypotInput schema.

    Returns:
        AegisCore standard prediction output dict.
    """
    validated = validate_input("honeypot", record)
    df = validated_to_df(validated)
    df["port"] = df["port"].astype(str)

    pipeline = load_model(MODEL_REGISTRY["honeypot"])
    le = load_model(LABEL_REGISTRY["honeypot"])

    y_pred_enc = pipeline.predict(df)[0]
    y_proba = pipeline.predict_proba(df)[0]
    confidence = float(np.max(y_proba))
    prediction = le.inverse_transform([y_pred_enc])[0]

    top_feats = get_top_features(pipeline, df, top_n=5)
    reason_codes = build_reason_codes(top_feats, "honeypot", record)
    explanation = build_explanation(prediction, reason_codes, "honeypot")

    rule_adjustments, severity_override = apply_honeypot_rules(record)
    severity = severity_override or SEVERITY_MAP.get(prediction, "info")
    risk_score = risk_score_from_proba(confidence)

    output = PredictionOutput(
        model="honeypot_classifier",
        prediction=prediction,
        confidence=round(confidence, 4),
        risk_score=risk_score,
        severity=severity,
        reason_codes=reason_codes,
        explanation=explanation,
        rule_adjustments=rule_adjustments if rule_adjustments else None,
    )
    return output.model_dump()


def predict_honeypot_batch(records: list) -> list:
    """Run inference on multiple honeypot records."""
    return [predict_honeypot(r) for r in records]
