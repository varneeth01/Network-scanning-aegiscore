"""
Network Anomaly Detection model definition.

SAFETY NOTICE: This model analyzes authorized telemetry only for defensive
anomaly detection. It does not generate scanning tools or attack traffic.
"""

from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.pipeline import Pipeline

from ..common.logger import get_logger
from ..common.utils import load_config
from ..preprocessing.encoders import build_preprocessor, get_feature_lists

logger = get_logger(__name__)


def build_network_unsupervised_pipeline() -> Pipeline:
    """Build the IsolationForest pipeline for unsupervised anomaly detection."""
    numeric_cols, binary_cols, categorical_cols = get_feature_lists("network")
    preprocessor = build_preprocessor(numeric_cols, binary_cols, categorical_cols)

    config = load_config()
    model_cfg = config["network"]
    seed = config["global"]["random_seed"]

    clf = IsolationForest(
        n_estimators=model_cfg["n_estimators"],
        max_samples=model_cfg["max_samples"],
        contamination=model_cfg["contamination"],
        random_state=seed,
        n_jobs=-1,
    )
    return Pipeline([("preprocessor", preprocessor), ("classifier", clf)])


def build_network_supervised_pipeline() -> Pipeline:
    """Build a supervised RandomForest pipeline for when labels are available."""
    numeric_cols, binary_cols, categorical_cols = get_feature_lists("network")
    preprocessor = build_preprocessor(numeric_cols, binary_cols, categorical_cols)
    seed = load_config()["global"]["random_seed"]
    clf = RandomForestClassifier(
        n_estimators=150,
        max_depth=None,
        class_weight="balanced",
        random_state=seed,
        n_jobs=-1,
    )
    return Pipeline([("preprocessor", preprocessor), ("classifier", clf)])
