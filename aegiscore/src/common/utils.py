"""Shared utility functions for AegisCore."""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

from .logger import get_logger

logger = get_logger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent.parent


def get_data_dir() -> Path:
    return BASE_DIR / "data"


def get_synthetic_dir() -> Path:
    return get_data_dir() / "synthetic"


def get_models_dir() -> Path:
    return get_data_dir() / "models"


def get_reports_dir() -> Path:
    return get_data_dir() / "reports"


def ensure_dirs() -> None:
    """Ensure all required directories exist."""
    for d in [get_synthetic_dir(), get_models_dir(), get_reports_dir()]:
        d.mkdir(parents=True, exist_ok=True)


def load_yaml(path: Path) -> Dict[str, Any]:
    with open(path, "r") as f:
        return yaml.safe_load(f)


def load_config() -> Dict[str, Any]:
    config_path = BASE_DIR / "configs" / "model_config.yaml"
    return load_yaml(config_path)


def load_feature_schema() -> Dict[str, Any]:
    schema_path = BASE_DIR / "configs" / "feature_schema.yaml"
    return load_yaml(schema_path)


def versioned_model_name(model_name: str, version: Optional[str] = None) -> str:
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    v = version or "v1"
    return f"{model_name}_{v}_{ts}"


def save_json(data: Dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    logger.info(f"Saved JSON to {path}")


def load_json(path: Path) -> Dict[str, Any]:
    with open(path, "r") as f:
        return json.load(f)


def risk_score_from_proba(proba: float, scale: int = 100) -> int:
    """Convert a probability [0,1] to an integer risk score [0, scale]."""
    return min(int(round(proba * scale)), scale)
