"""
Synthetic data generator for the Security Misconfiguration / Exposure Risk model.

SAFETY NOTICE: This module generates synthetic security posture data based on
publicly-known security best practices and configuration indicators only.
It does not generate exploit code or real-target scanning instructions.
"""

import numpy as np
import pandas as pd
from typing import Optional

from ..common.logger import get_logger
from ..common.io import save_dataframe

logger = get_logger(__name__)

LABELS = ["low", "medium", "high", "critical"]
LABEL_WEIGHTS = [0.30, 0.35, 0.25, 0.10]


def _risk_label(score: float) -> str:
    if score < 0.25:
        return "low"
    elif score < 0.55:
        return "medium"
    elif score < 0.80:
        return "high"
    return "critical"


def _compute_risk_score(row: dict, rng: np.random.Generator) -> float:
    """Compute a heuristic risk score from the posture features."""
    score = 0.0
    score += row["missing_hsts"] * 0.04
    score += row["missing_csp"] * 0.03
    score += row["missing_x_content_type_options"] * 0.02
    score += row["insecure_cookie_flags"] * 0.04
    score += row["weak_tls"] * 0.07
    score += row["deprecated_protocol_present"] * 0.06
    score += row["admin_interface_exposed"] * 0.10
    score += row["risky_management_port_exposed"] * 0.08
    score += min(row["open_port_count"] / 50.0, 0.08)
    score += min(row["legacy_service_count"] / 10.0, 0.06)
    score += min(row["dependency_vuln_count"] / 30.0, 0.07)
    score += row["secrets_detected"] * 0.12
    score += row["public_bucket_like_flag"] * 0.09
    score += row["authz_gap_indicator"] * 0.06
    score += row["excessive_cors_flag"] * 0.04
    score += row["debug_banner_present"] * 0.03
    score += row["default_credentials_risk"] * 0.11
    score += row["segmentation_risk_score"] * 0.08
    noise = rng.uniform(-0.05, 0.05)
    return max(0.0, min(1.0, score + noise))


def generate_posture_data(
    n_samples: int = 8000,
    seed: int = 42,
    save: bool = True,
) -> pd.DataFrame:
    """Generate synthetic security posture assessment data."""
    rng = np.random.default_rng(seed)
    rows = []

    for _ in range(n_samples):
        row = {
            "missing_hsts": int(rng.random() < 0.5),
            "missing_csp": int(rng.random() < 0.55),
            "missing_x_content_type_options": int(rng.random() < 0.45),
            "insecure_cookie_flags": int(rng.random() < 0.4),
            "weak_tls": int(rng.random() < 0.3),
            "deprecated_protocol_present": int(rng.random() < 0.25),
            "admin_interface_exposed": int(rng.random() < 0.2),
            "risky_management_port_exposed": int(rng.random() < 0.25),
            "open_port_count": int(rng.integers(1, 50)),
            "legacy_service_count": int(rng.integers(0, 10)),
            "dependency_vuln_count": int(rng.integers(0, 30)),
            "secrets_detected": int(rng.random() < 0.1),
            "public_bucket_like_flag": int(rng.random() < 0.08),
            "authz_gap_indicator": int(rng.random() < 0.15),
            "excessive_cors_flag": int(rng.random() < 0.2),
            "debug_banner_present": int(rng.random() < 0.15),
            "default_credentials_risk": int(rng.random() < 0.08),
            "segmentation_risk_score": float(rng.uniform(0.0, 1.0)),
        }
        risk_score = _compute_risk_score(row, rng)
        row["risk_score_raw"] = risk_score
        row["label"] = _risk_label(risk_score)
        rows.append(row)

    df = pd.DataFrame(rows)

    logger.info(f"Generated {len(df)} posture samples")
    logger.info(f"Label distribution:\n{df['label'].value_counts()}")

    if save:
        save_dataframe(df, "posture_synthetic")

    return df
