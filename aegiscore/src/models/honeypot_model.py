"""
Honeypot Attack Classifier model definition.

SAFETY NOTICE: This model is for defensive classification of honeypot
interaction events only. It does not generate attack code or assist
with offensive operations.
"""

from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.pipeline import Pipeline

try:
    from xgboost import XGBClassifier
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False

from ..common.logger import get_logger
from ..common.utils import load_config
from ..preprocessing.encoders import build_preprocessor, get_feature_lists

logger = get_logger(__name__)


def build_honeypot_pipeline() -> Pipeline:
    """Build the full sklearn pipeline for the honeypot classifier."""
    numeric_cols, binary_cols, categorical_cols = get_feature_lists("honeypot")
    preprocessor = build_preprocessor(numeric_cols, binary_cols, categorical_cols)

    config = load_config()["honeypot"]

    if HAS_XGBOOST:
        logger.info("Using XGBoost for Honeypot Classifier")
        clf = XGBClassifier(
            n_estimators=config["n_estimators"],
            max_depth=config["max_depth"],
            learning_rate=config["learning_rate"],
            subsample=config["subsample"],
            colsample_bytree=config["colsample_bytree"],
            use_label_encoder=False,
            eval_metric="mlogloss",
            random_state=load_config()["global"]["random_seed"],
            n_jobs=-1,
        )
    else:
        logger.info("XGBoost not available, using GradientBoostingClassifier")
        clf = GradientBoostingClassifier(
            n_estimators=config["n_estimators"],
            max_depth=config["max_depth"],
            learning_rate=config["learning_rate"],
            subsample=config["subsample"],
            random_state=load_config()["global"]["random_seed"],
        )

    pipeline = Pipeline([
        ("preprocessor", preprocessor),
        ("classifier", clf),
    ])
    return pipeline


def build_honeypot_baseline() -> Pipeline:
    """Build a RandomForest baseline for the honeypot classifier."""
    numeric_cols, binary_cols, categorical_cols = get_feature_lists("honeypot")
    preprocessor = build_preprocessor(numeric_cols, binary_cols, categorical_cols)
    seed = load_config()["global"]["random_seed"]

    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=None,
        class_weight="balanced",
        random_state=seed,
        n_jobs=-1,
    )
    return Pipeline([("preprocessor", preprocessor), ("classifier", clf)])
