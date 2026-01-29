"""
©AngelaMos | 2025
Authentication service for user registration and login
"""

from __future__ import annotations

from datetime import timedelta
from sqlalchemy.orm import Session
from fastapi import HTTPException, status

from config import settings
from core.security import (
    create_access_token,
    hash_password,
    verify_password,
)
from schemas.user_schemas import (
    TokenResponse,
    UserCreate,
    UserLogin,
    UserResponse,
)
from repositories.user_repository import UserRepository


class AuthService:
    """
    User registration, login, and token generation
    """

    @staticmethod
    def register_user(db: Session, user_data: UserCreate) -> UserResponse:
        """
        Register a new user

        Args:
            db: Database session
            user_data: User registration data

        Returns:
            UserResponse: Created user data
        """
        existing_user = UserRepository.get_by_email(db, user_data.email)
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered",
            )

        hashed_password = hash_password(user_data.password)

        user = UserRepository.create_user(
            db=db,
            email=user_data.email,
            hashed_password=hashed_password,
        )

        return UserResponse.model_validate(user)

    @staticmethod
    def login_user(db: Session, login_data: UserLogin) -> TokenResponse:
        """
        Authenticate user and generate access token

        Args:
            db: Database session
            login_data: User login credentials

        Returns:
            TokenResponse: JWT access token
        """
        user = UserRepository.get_by_email(db, login_data.email)

        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
            )

        if not verify_password(login_data.password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is inactive",
            )

        access_token = create_access_token(
            data={"sub": user.email},
            expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        )

        return TokenResponse(access_token=access_token, token_type="bearer")

    @staticmethod
    def get_user_by_email(db: Session, email: str) -> UserResponse | None:
        """
        Get user by email address

        Args:
            db: Database session
            email: User email

        Returns:
            UserResponse | None: User data or None if not found
        """
        user = UserRepository.get_by_email(db, email)
        if user:
            return UserResponse.model_validate(user)
        return None
