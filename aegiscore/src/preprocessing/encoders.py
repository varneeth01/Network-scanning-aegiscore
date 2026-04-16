"""Feature encoding and preprocessing pipelines for AegisCore."""

from typing import List, Tuple

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder, OneHotEncoder, StandardScaler

from ..common.logger import get_logger
from ..common.utils import load_feature_schema

logger = get_logger(__name__)


def get_feature_lists(model_name: str) -> Tuple[List[str], List[str], List[str]]:
    """Return (numeric_cols, binary_cols, categorical_cols) for a given model."""
    schema = load_feature_schema()
    model_schema = schema[model_name]
    return (
        model_schema.get("numeric", []),
        model_schema.get("binary", []),
        model_schema.get("categorical", []),
    )


def build_preprocessor(
    numeric_cols: List[str],
    binary_cols: List[str],
    categorical_cols: List[str],
) -> ColumnTransformer:
    """Build a sklearn ColumnTransformer for mixed feature types."""
    transformers = []

    if numeric_cols:
        transformers.append(("num", StandardScaler(), numeric_cols))

    if categorical_cols:
        transformers.append((
            "cat",
            OneHotEncoder(handle_unknown="ignore", sparse_output=False),
            categorical_cols,
        ))

    if binary_cols:
        transformers.append(("bin", "passthrough", binary_cols))

    return ColumnTransformer(transformers=transformers, remainder="drop")


def encode_labels(y: pd.Series) -> Tuple[np.ndarray, LabelEncoder]:
    """Encode string labels to integers."""
    le = LabelEncoder()
    y_enc = le.fit_transform(y)
    return y_enc, le
