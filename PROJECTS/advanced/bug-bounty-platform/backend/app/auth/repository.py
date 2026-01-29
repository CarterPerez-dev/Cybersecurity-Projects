"""
ⒸAngelaMos | 2025
repository.py
"""

from uuid import UUID
from datetime import UTC, datetime

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from .RefreshToken import RefreshToken
from core.base_repository import BaseRepository


class RefreshTokenRepository(BaseRepository[RefreshToken]):
    """
    Repository for RefreshToken model database operations
    """
    model = RefreshToken

    @classmethod
    async def get_by_hash(
        cls,
        session: AsyncSession,
        token_hash: str,
    ) -> RefreshToken | None:
        """
        Get refresh token by its hash
        """
        result = await session.execute(
            select(RefreshToken).where(
                RefreshToken.token_hash == token_hash
            )
        )
        return result.scalars().first()

    @classmethod
    async def get_valid_by_hash(
        cls,
        session: AsyncSession,
        token_hash: str,
    ) -> RefreshToken | None:
        """
        Get valid (not revoked, not expired) refresh token by hash
        """
        result = await session.execute(
            select(RefreshToken).where(
                RefreshToken.token_hash == token_hash,
                RefreshToken.is_revoked == False,
                RefreshToken.expires_at > datetime.now(UTC),
            )
        )
        return result.scalars().first()

    @classmethod
    async def create_token(
        cls,
        session: AsyncSession,
        user_id: UUID,
        token_hash: str,
        family_id: UUID,
        expires_at: datetime,
        device_id: str | None = None,
        device_name: str | None = None,
        ip_address: str | None = None,
    ) -> RefreshToken:
        """
        Create a new refresh token
        """
        token = RefreshToken(
            user_id = user_id,
            token_hash = token_hash,
            family_id = family_id,
            expires_at = expires_at,
            device_id = device_id,
            device_name = device_name,
            ip_address = ip_address,
        )
        session.add(token)
        await session.flush()
        await session.refresh(token)
        return token

    @classmethod
    async def revoke_token(
        cls,
        session: AsyncSession,
        token: RefreshToken,
    ) -> RefreshToken:
        """
        Revoke a single token
        """
        token.revoke()
        await session.flush()
        await session.refresh(token)
        return token

    @classmethod
    async def revoke_family(
        cls,
        session: AsyncSession,
        family_id: UUID,
    ) -> int:
        """
        Revoke all tokens in a family (for replay attack response)

        Returns count of revoked tokens
        """
        result = await session.execute(
            update(RefreshToken).where(
                RefreshToken.family_id == family_id,
                RefreshToken.is_revoked == False,
            ).values(is_revoked = True,
                     revoked_at = datetime.now(UTC))
        )
        await session.flush()
        return result.rowcount or 0

    @classmethod
    async def revoke_all_user_tokens(
        cls,
        session: AsyncSession,
        user_id: UUID,
    ) -> int:
        """
        Revoke all tokens for a user (logout all devices)

        Returns count of revoked tokens
        """
        result = await session.execute(
            update(RefreshToken).where(
                RefreshToken.user_id == user_id,
                RefreshToken.is_revoked == False,
            ).values(is_revoked = True,
                     revoked_at = datetime.now(UTC))
        )
        await session.flush()
        return result.rowcount or 0

    @classmethod
    async def get_user_active_sessions(
        cls,
        session: AsyncSession,
        user_id: UUID,
    ) -> list[RefreshToken]:
        """
        Get all active sessions for a user
        """
        result = await session.execute(
            select(RefreshToken).where(
                RefreshToken.user_id == user_id,
                RefreshToken.is_revoked == False,
                RefreshToken.expires_at > datetime.now(UTC),
            )
        )
        return list(result.scalars().all())

    @classmethod
    async def cleanup_expired(
        cls,
        session: AsyncSession,
    ) -> int:
        """
        Delete expired tokens (for maintenance job)

        Returns count of deleted tokens
        """
        result = await session.execute(
            select(RefreshToken).where(
                RefreshToken.expires_at < datetime.now(UTC)
            )
        )
        tokens = result.scalars().all()
        for token in tokens:
            await session.delete(token)
        await session.flush()
        return len(tokens)
