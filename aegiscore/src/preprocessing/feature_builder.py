"""Feature selection and transformation helpers for AegisCore."""

from typing import List, Tuple

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from ..common.logger import get_logger
from ..common.utils import load_config

logger = get_logger(__name__)


def prepare_xy(
    df: pd.DataFrame,
    feature_cols: List[str],
    label_col: str = "label",
) -> Tuple[pd.DataFrame, pd.Series]:
    """Extract feature matrix and target from a dataframe."""
    missing = [c for c in feature_cols if c not in df.columns]
    if missing:
        raise ValueError(f"Missing feature columns: {missing}")
    X = df[feature_cols].copy()
    y = df[label_col].copy()
    return X, y


def split_data(
    X: pd.DataFrame,
    y: pd.Series,
    test_size: float = 0.2,
    seed: int = 42,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series]:
    """Stratified train/test split."""
    try:
        return train_test_split(X, y, test_size=test_size, random_state=seed, stratify=y)
    except ValueError:
        logger.warning("Stratified split failed, falling back to random split.")
        return train_test_split(X, y, test_size=test_size, random_state=seed)


def handle_missing(df: pd.DataFrame, numeric_cols: List[str], categorical_cols: List[str]) -> pd.DataFrame:
    """Fill missing values for numeric and categorical columns."""
    df = df.copy()
    for col in numeric_cols:
        if col in df.columns:
            df[col] = df[col].fillna(df[col].median())
    for col in categorical_cols:
        if col in df.columns:
            df[col] = df[col].fillna("unknown")
    return df
