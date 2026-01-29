"""
ⒸAngelaMos | 2025
base.py
"""

from typing import Any
from collections.abc import Callable
from decimal import Decimal
from uuid import UUID
from datetime import datetime

from pydantic import (
    BaseModel,
    ConfigDict,
    field_serializer,
)


class BaseSchema(BaseModel):
    """
    Base schema with common configuration
    """
    model_config = ConfigDict(
        from_attributes = True,
        str_strip_whitespace = True,
    )

    @field_serializer('*', mode = 'wrap', when_used = 'json')
    def serialize_decimals(
        self,
        value: Any,
        nxt: Callable[[Any],
                      Any],
        _info: Any,
    ) -> Any:
        """
        Serialize Decimal fields as float for JSON compatibility
        """
        if isinstance(value, Decimal):
            return float(value)
        return nxt(value)


class BaseResponseSchema(BaseSchema):
    """
    Base schema for API responses with common fields
    """
    id: UUID
    created_at: datetime
    updated_at: datetime | None = None
