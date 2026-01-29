"""
ⒸAngelaMos | 2025
User model for authentication and user management
"""

from sqlalchemy import (
    Boolean,
    Column,
    String,
)

from config import settings
from .Base import BaseModel


class User(BaseModel):
    """
    Stores authentication credentials and user information
    """

    __tablename__ = "users"

    email = Column(
        String(settings.EMAIL_MAX_LENGTH),
        unique = True,
        nullable = False,
        index = True,
    )
    hashed_password = Column(String, nullable = False)
    is_active = Column(Boolean, default = True, nullable = False)

    def __repr__(self) -> str:
        """
        String representation of User
        """
        return f"<User(id={self.id}, email={self.email})>"

    @property
    def is_authenticated(self) -> bool:
        """
        Check if user is active and authenticated

        Returns:
            bool: True if user is active
        """
        return self.is_active
