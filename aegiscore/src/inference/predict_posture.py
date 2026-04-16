"""
Inference script for the Security Misconfiguration / Exposure Risk model.

SAFETY NOTICE: Analyzes authorized configuration data only. Does not
generate exploit code or bypass guidance.
"""

from typing import Any, Dict, List

import numpy as np

from ..common.io import load_model
from ..common.logger import get_logger
from ..common.schemas import PredictionOutput, SEVERITY_MAP
from ..common.utils import risk_score_from_proba
from ..explainability.explanation_engine import build_explanation, build_reason_codes
from ..explainability.feature_importance import get_top_features
from ..models.registry import LABEL_REGISTRY, MODEL_REGISTRY
from ..preprocessing.validators import validate_input, validated_to_df
from ..rules.posture_rules import apply_posture_rules, generate_remediation_priorities

logger = get_logger(__name__)


def predict_posture(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run security posture risk assessment on a configuration record.

    Args:
        record: Dict matching PostureInput schema.

    Returns:
        AegisCore standard prediction output dict with remediation priorities.
    """
    validated = validate_input("posture", record)
    df = validated_to_df(validated)

    pipeline = load_model(MODEL_REGISTRY["posture"])
    le = load_model(LABEL_REGISTRY["posture"])

    y_pred_enc = pipeline.predict(df)[0]
    y_proba = pipeline.predict_proba(df)[0]
    confidence = float(np.max(y_proba))
    ml_prediction = le.inverse_transform([y_pred_enc])[0]

    top_feats = get_top_features(pipeline, df, top_n=5)
    reason_codes = build_reason_codes(top_feats, "posture", record)

    rule_adjustments, severity_override = apply_posture_rules(record)
    severity = severity_override or SEVERITY_MAP.get(ml_prediction, "medium")

    remediation_priorities = generate_remediation_priorities(record)

    final_prediction = ml_prediction
    if severity_override:
        severity_to_label = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
        final_prediction = severity_to_label.get(severity_override, ml_prediction)

    explanation = build_explanation(final_prediction, reason_codes, "posture")
    risk_score = risk_score_from_proba(confidence)

    output = PredictionOutput(
        model="posture_risk",
        prediction=final_prediction,
        confidence=round(confidence, 4),
        risk_score=risk_score,
        severity=severity,
        reason_codes=reason_codes,
        explanation=explanation,
        rule_adjustments=(rule_adjustments + remediation_priorities) if rule_adjustments else remediation_priorities,
    )
    return output.model_dump()


def predict_posture_batch(records: list) -> list:
    return [predict_posture(r) for r in records]
