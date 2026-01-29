"""
ⒸAngelaMos | 2025
service.py
"""

import uuid6
from sqlalchemy.ext.asyncio import (
    AsyncSession,
)

from core.exceptions import (
    InvalidCredentials,
    TokenError,
    TokenRevokedError,
)
from core.security import (
    hash_token,
    create_access_token,
    create_refresh_token,
    verify_password_with_timing_safety,
)
from user.User import User
from user.repository import UserRepository
from .repository import RefreshTokenRepository
from .schemas import (
    TokenResponse,
    TokenWithUserResponse,
)
from user.schemas import UserResponse


class AuthService:
    """
    Business logic for authentication operations
    """
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def authenticate(
        self,
        email: str,
        password: str,
        device_id: str | None = None,
        device_name: str | None = None,
        ip_address: str | None = None,
    ) -> tuple[str,
               str,
               User]:
        """
        Authenticate user and create tokens
        """
        user = await UserRepository.get_by_email(self.session, email)
        hashed_password = user.hashed_password if user else None

        is_valid, new_hash = await verify_password_with_timing_safety(
            password, hashed_password
        )

        if not is_valid or user is None:
            raise InvalidCredentials()

        if not user.is_active:
            raise InvalidCredentials()

        if new_hash:
            await UserRepository.update_password(
                self.session,
                user,
                new_hash
            )

        access_token = create_access_token(user.id, user.token_version)

        family_id = uuid6.uuid7()
        raw_refresh, token_hash, expires_at = create_refresh_token(user.id, family_id)

        await RefreshTokenRepository.create_token(
            self.session,
            user_id = user.id,
            token_hash = token_hash,
            family_id = family_id,
            expires_at = expires_at,
            device_id = device_id,
            device_name = device_name,
            ip_address = ip_address,
        )

        return access_token, raw_refresh, user

    async def login(
        self,
        email: str,
        password: str,
        device_id: str | None = None,
        device_name: str | None = None,
        ip_address: str | None = None,
    ) -> tuple[TokenWithUserResponse,
               str]:
        """
        Login and return tokens with user data
        """
        access_token, refresh_token, user = await self.authenticate(
            email,
            password,
            device_id,
            device_name,
            ip_address,
        )

        response = TokenWithUserResponse(
            access_token = access_token,
            user = UserResponse.model_validate(user),
        )
        return response, refresh_token

    async def refresh_tokens(
        self,
        refresh_token: str,
        device_id: str | None = None,
        device_name: str | None = None,
        ip_address: str | None = None,
    ) -> tuple[TokenResponse,
               str]:
        """
        Refresh access token using refresh token

        Implements token rotation with replay attack detection
        """
        token_hash = hash_token(refresh_token)
        stored_token = await RefreshTokenRepository.get_by_hash(
            self.session,
            token_hash
        )

        if stored_token is None:
            raise TokenError(message = "Invalid refresh token")

        if stored_token.is_revoked:
            await RefreshTokenRepository.revoke_family(
                self.session,
                stored_token.family_id
            )
            raise TokenRevokedError()

        if stored_token.is_expired:
            raise TokenError(message = "Refresh token expired")

        user = await UserRepository.get_by_id(
            self.session,
            stored_token.user_id
        )
        if user is None or not user.is_active:
            raise TokenError(message = "User not found or inactive")

        await RefreshTokenRepository.revoke_token(
            self.session,
            stored_token
        )

        access_token = create_access_token(user.id, user.token_version)

        new_raw_token, new_hash, expires_at = create_refresh_token(
            user.id, stored_token.family_id
        )

        await RefreshTokenRepository.create_token(
            self.session,
            user_id = user.id,
            token_hash = new_hash,
            family_id = stored_token.family_id,
            expires_at = expires_at,
            device_id = device_id,
            device_name = device_name,
            ip_address = ip_address,
        )

        return TokenResponse(access_token = access_token), new_raw_token

    async def logout(
        self,
        refresh_token: str,
    ) -> None:
        """
        Logout by revoking refresh token

        Silently succeeds if token is already revoked or doesn't exist
        """
        token_hash = hash_token(refresh_token)
        stored_token = await RefreshTokenRepository.get_by_hash(
            self.session,
            token_hash
        )

        if stored_token and not stored_token.is_revoked:
            await RefreshTokenRepository.revoke_token(
                self.session,
                stored_token
            )

    async def logout_all(
        self,
        user: User,
    ) -> int:
        """
        Logout from all devices

        Returns count of revoked sessions
        """
        await UserRepository.increment_token_version(self.session, user)
        return await RefreshTokenRepository.revoke_all_user_tokens(
            self.session,
            user.id
        )
