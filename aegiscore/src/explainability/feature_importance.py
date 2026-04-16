"""
Feature importance extraction for AegisCore models.

Uses SHAP when available, otherwise falls back to permutation importance
or tree-based built-in feature importances.
"""

from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.inspection import permutation_importance
from sklearn.pipeline import Pipeline

from ..common.logger import get_logger

logger = get_logger(__name__)

try:
    import shap
    HAS_SHAP = True
except ImportError:
    HAS_SHAP = False
    logger.warning("SHAP not available. Using permutation importance fallback.")


def get_feature_names_from_pipeline(pipeline: Pipeline, X: pd.DataFrame) -> List[str]:
    """Extract feature names from a fitted ColumnTransformer pipeline step."""
    try:
        preprocessor = pipeline.named_steps["preprocessor"]
        feature_names = preprocessor.get_feature_names_out()
        return list(feature_names)
    except Exception:
        return list(X.columns)


def get_tree_feature_importance(
    pipeline: Pipeline,
    X: pd.DataFrame,
    top_n: int = 10,
) -> List[Tuple[str, float]]:
    """Extract built-in feature importances from tree-based classifiers."""
    try:
        clf = pipeline.named_steps["classifier"]
        feature_names = get_feature_names_from_pipeline(pipeline, X)
        importances = clf.feature_importances_
        pairs = sorted(zip(feature_names, importances), key=lambda x: x[1], reverse=True)
        return pairs[:top_n]
    except Exception as e:
        logger.warning(f"Could not extract tree feature importances: {e}")
        return []


def get_shap_importance(
    pipeline: Pipeline,
    X: pd.DataFrame,
    top_n: int = 10,
) -> List[Tuple[str, float]]:
    """Use SHAP TreeExplainer to get feature importance."""
    if not HAS_SHAP:
        return get_tree_feature_importance(pipeline, X, top_n)

    try:
        preprocessor = pipeline.named_steps["preprocessor"]
        clf = pipeline.named_steps["classifier"]
        X_transformed = preprocessor.transform(X.head(200))
        feature_names = get_feature_names_from_pipeline(pipeline, X)

        explainer = shap.TreeExplainer(clf)
        shap_values = explainer.shap_values(X_transformed)

        if isinstance(shap_values, list):
            mean_abs = np.mean([np.abs(sv).mean(axis=0) for sv in shap_values], axis=0)
        else:
            mean_abs = np.abs(shap_values).mean(axis=0)

        pairs = sorted(zip(feature_names, mean_abs), key=lambda x: x[1], reverse=True)
        return pairs[:top_n]
    except Exception as e:
        logger.warning(f"SHAP failed: {e}. Falling back to tree importance.")
        return get_tree_feature_importance(pipeline, X, top_n)


def get_top_features(
    pipeline: Pipeline,
    X: pd.DataFrame,
    top_n: int = 3,
) -> List[Tuple[str, float]]:
    """Return top N feature (name, importance) pairs for a given pipeline."""
    return get_shap_importance(pipeline, X, top_n)


def get_anomaly_contributions(
    X_record: pd.DataFrame,
    feature_means: pd.Series,
    feature_stds: pd.Series,
    top_n: int = 3,
) -> List[Tuple[str, float]]:
    """For unsupervised models, rank features by z-score deviation."""
    z_scores = {}
    for col in X_record.columns:
        val = X_record[col].iloc[0]
        mean = feature_means.get(col, 0.0)
        std = feature_stds.get(col, 1.0)
        if std > 0:
            z_scores[col] = abs((val - mean) / std)
        else:
            z_scores[col] = 0.0
    sorted_feats = sorted(z_scores.items(), key=lambda x: x[1], reverse=True)
    return sorted_feats[:top_n]
