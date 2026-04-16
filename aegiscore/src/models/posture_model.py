"""
Security Misconfiguration / Exposure Risk model definition.

SAFETY NOTICE: This model analyzes authorized configuration data only
for defensive risk assessment. It does not generate exploit code or
provide guidance for bypassing security controls.
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


def build_posture_pipeline() -> Pipeline:
    """Build the full sklearn pipeline for the posture risk classifier."""
    numeric_cols, binary_cols, categorical_cols = get_feature_lists("posture")
    preprocessor = build_preprocessor(numeric_cols, binary_cols, categorical_cols)

    config = load_config()
    model_cfg = config["posture"]
    seed = config["global"]["random_seed"]

    if HAS_XGBOOST:
        logger.info("Using XGBoost for Posture Risk Classifier")
        clf = XGBClassifier(
            n_estimators=model_cfg["n_estimators"],
            max_depth=model_cfg["max_depth"],
            learning_rate=model_cfg["learning_rate"],
            subsample=model_cfg["subsample"],
            use_label_encoder=False,
            eval_metric="mlogloss",
            random_state=seed,
            n_jobs=-1,
        )
    else:
        clf = GradientBoostingClassifier(
            n_estimators=model_cfg["n_estimators"],
            max_depth=model_cfg["max_depth"],
            learning_rate=model_cfg["learning_rate"],
            subsample=model_cfg["subsample"],
            random_state=seed,
        )

    return Pipeline([("preprocessor", preprocessor), ("classifier", clf)])


def build_posture_baseline() -> Pipeline:
    """Build a RandomForest baseline for posture risk."""
    numeric_cols, binary_cols, categorical_cols = get_feature_lists("posture")
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
