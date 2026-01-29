"""
ⒸAngelaMos | 2025
errors.py
"""

from typing import ClassVar
from pydantic import Field, ConfigDict
from core.base_schema import BaseSchema


class ErrorDetail(BaseSchema):
    """
    Standard error response format
    """
    detail: str = Field(..., description = "Human readable error message")
    type: str = Field(..., description = "Exception class name")

    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra = {
            "examples": [
                {
                    "detail": "User with id '123' not found",
                    "type": "UserNotFound"
                }
            ]
        }
    )
