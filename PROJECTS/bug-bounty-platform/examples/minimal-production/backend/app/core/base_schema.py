"""
ⒸAngelaMos | 2025
base.py
"""

from uuid import UUID
from datetime import datetime

from pydantic import (
    BaseModel,
    ConfigDict,
)


class BaseSchema(BaseModel):
    """
    Base schema with common configuration
    """
    model_config = ConfigDict(
        from_attributes = True,
        str_strip_whitespace = True,
    )


class BaseResponseSchema(BaseSchema):
    """
    Base schema for API responses with common fields
    """
    id: UUID
    created_at: datetime
    updated_at: datetime | None = None
