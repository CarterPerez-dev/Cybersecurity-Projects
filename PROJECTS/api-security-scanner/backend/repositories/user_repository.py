"""
ⒸAngelaMos | 2025
User repository for database operations
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from config import settings
from models.User import User


class UserRepository:
    """
    Repository for User database operations
    """
    @staticmethod
    def get_by_id(db: Session, user_id: int) -> User | None:
        """
        Get user by ID

        Args:
            db: Database session
            user_id: User ID

        Returns:
            User | None: User instance or None if not found
        """
        return db.query(User).filter(User.id == user_id).first()

    @staticmethod
    def get_by_email(db: Session, email: str) -> User | None:
        """
        Get user by email address

        Args:
            db: Database session
            email: User email address

        Returns:
            User | None: User instance or None if not found
        """
        return db.query(User).filter(User.email == email).first()

    @staticmethod
    def create_user(
        db: Session,
        email: str,
        hashed_password: str,
        commit: bool = True
    ) -> User:
        """
        Create a new user

        Args:
            db: Database session
            email: User email address
            hashed_password: Bcrypt hashed password
            commit: Whether to commit the transaction

        Returns:
            User: Created user instance
        """
        user = User(email = email, hashed_password = hashed_password)
        db.add(user)
        if commit:
            db.commit()
            db.refresh(user)
        return user

    @staticmethod
    def get_all_active(
        db: Session,
        skip: int = 0,
        limit: int | None = None
    ) -> list[User]:
        """
        Get all active users with pagination

        Args:
            db: Database session
            skip: Number of records to skip
            limit: Maximum number of records to return (DEFAULT_PAGINATION_LIMIT)

        Returns:
            list[User]: List of active users
        """
        if limit is None:
            limit = settings.DEFAULT_PAGINATION_LIMIT

        return db.query(User).filter(User.is_active
                                     ).offset(skip).limit(limit).all()

    @staticmethod
    def update_active_status(
        db: Session,
        user_id: int,
        is_active: bool,
        commit: bool = True
    ) -> User | None:
        """
        Update user active status

        Args:
            db: Database session
            user_id: User ID
            is_active: New active status
            commit: Whether to commit the transaction

        Returns:
            User | None: Updated user or None if not found
        """
        user = UserRepository.get_by_id(db, user_id)
        if user:
            user.is_active = is_active
            if commit:
                db.commit()
                db.refresh(user)
        return user

    @staticmethod
    def delete(
        db: Session,
        user_id: int,
        commit: bool = True
    ) -> bool:
        """
        Delete a user

        Args:
            db: Database session
            user_id: User ID to delete
            commit: Whether to commit the transaction

        Returns:
            bool: True if deleted, False if not found
        """
        user = UserRepository.get_by_id(db, user_id)
        if user:
            db.delete(user)
            if commit:
                db.commit()
            return True
        return False
