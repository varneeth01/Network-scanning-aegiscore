"""Input validation using Pydantic schemas for AegisCore inference."""

from typing import Any, Dict, Type

from pydantic import BaseModel, ValidationError

from ..common.logger import get_logger
from ..common.schemas import (
    HoneypotInput,
    MalwareInput,
    NetworkInput,
    PostureInput,
)

logger = get_logger(__name__)

SCHEMA_MAP: Dict[str, Type[BaseModel]] = {
    "honeypot": HoneypotInput,
    "malware": MalwareInput,
    "network": NetworkInput,
    "posture": PostureInput,
}


def validate_input(model_name: str, data: Dict[str, Any]) -> BaseModel:
    """Validate inference input dict against the appropriate schema."""
    schema = SCHEMA_MAP.get(model_name)
    if schema is None:
        raise ValueError(f"Unknown model: {model_name}. Valid: {list(SCHEMA_MAP.keys())}")
    try:
        return schema(**data)
    except ValidationError as e:
        raise ValueError(f"Input validation failed for '{model_name}':\n{e}") from e


def validated_to_df(validated: BaseModel) -> "pd.DataFrame":
    """Convert a Pydantic model instance to a single-row DataFrame."""
    import pandas as pd
    return pd.DataFrame([validated.model_dump()])
