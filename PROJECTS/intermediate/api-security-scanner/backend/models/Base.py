"""
ⒸAngelaMos | 2025
Base model class
Common fields and methods for all models
"""

from typing import Any
from sqlalchemy import (
    Column,
    DateTime,
    Integer,
)
from datetime import datetime, UTC
from sqlalchemy.ext.declarative import declared_attr

from core.database import Base


class BaseModel(Base):
    """
    Abstract base model with common fields and methods
    All models inherit from this class
    """

    __abstract__ = True

    id = Column(
        Integer,
        primary_key = True,
        index = True,
        autoincrement = True
    )
    created_at = Column(
        DateTime(timezone = True),
        default = lambda: datetime.now(UTC)
    )
    updated_at = Column(
        DateTime(timezone = True),
        default = lambda: datetime.now(UTC),
        onupdate = lambda: datetime.now(UTC),
    )

    @declared_attr
    def __tablename__(cls) -> str:
        """
        Auto-generate table name from class name
        """
        return cls.__name__.lower()

    def to_dict(self) -> dict[str, Any]:
        """
        Convert model instance to dictionary

        Returns:
            dict: Dictionary representation of the model
        """
        return {
            column.name: getattr(self,
                                 column.name)
            for column in self.__table__.columns
        }

    def update(self, **kwargs: Any) -> None:
        """
        Update model fields from keyword arguments

        Args:
            **kwargs: Field names and values to update
        """
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
        self.updated_at = datetime.now(UTC)

    def __repr__(self) -> str:
        """
        String representation of model
        """
        return f"<{self.__class__.__name__}(id={self.id})>"
