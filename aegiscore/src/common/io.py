"""I/O helpers for model artifacts and data in AegisCore."""

from pathlib import Path
from typing import Any, Tuple

import joblib
import pandas as pd

from .logger import get_logger
from .utils import get_models_dir, get_synthetic_dir

logger = get_logger(__name__)


def save_model(pipeline: Any, name: str) -> Path:
    """Persist a sklearn pipeline or model to disk."""
    models_dir = get_models_dir()
    models_dir.mkdir(parents=True, exist_ok=True)
    path = models_dir / f"{name}.joblib"
    joblib.dump(pipeline, path)
    logger.info(f"Model saved: {path}")
    return path


def load_model(name: str) -> Any:
    """Load a persisted model by base name (without .joblib)."""
    models_dir = get_models_dir()
    path = models_dir / f"{name}.joblib"
    if not path.exists():
        raise FileNotFoundError(f"Model not found: {path}")
    pipeline = joblib.load(path)
    logger.info(f"Model loaded: {path}")
    return pipeline


def save_dataframe(df: pd.DataFrame, name: str) -> Path:
    """Save a DataFrame to the synthetic data directory."""
    synthetic_dir = get_synthetic_dir()
    synthetic_dir.mkdir(parents=True, exist_ok=True)
    path = synthetic_dir / f"{name}.csv"
    df.to_csv(path, index=False)
    logger.info(f"Data saved: {path} ({len(df)} rows)")
    return path


def load_dataframe(name: str, directory: Path = None) -> pd.DataFrame:
    """Load a CSV from the synthetic data directory or a given directory."""
    base = directory or get_synthetic_dir()
    path = base / f"{name}.csv"
    if not path.exists():
        raise FileNotFoundError(f"Data file not found: {path}")
    df = pd.read_csv(path)
    logger.info(f"Loaded data: {path} ({len(df)} rows)")
    return df
