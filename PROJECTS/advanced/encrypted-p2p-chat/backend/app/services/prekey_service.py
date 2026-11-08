"""
©AngelaMos | 2026
prekey_service.py
"""

import logging
from datetime import (
    UTC,
    datetime,
    timedelta,
)
from dataclasses import dataclass
from uuid import UUID

from sqlmodel import select
from sqlalchemy.exc import IntegrityError
from sqlmodel.ext.asyncio.session import AsyncSession

from app.config import (
    SIGNED_PREKEY_ROTATION_HOURS,
)
from app.core.exceptions import (
    DatabaseError,
    InvalidDataError,
    UserNotFoundError,
)
from app.models.User import User
from app.models.IdentityKey import IdentityKey
from app.models.SignedPrekey import SignedPrekey
from app.models.OneTimePrekey import OneTimePrekey


logger = logging.getLogger(__name__)


@dataclass
class PreKeyBundle:
    """
    Recipient prekey bundle for X3DH protocol
    """
    identity_key: str
    identity_key_ed25519: str
    signed_prekey: str
    signed_prekey_signature: str
    one_time_prekey: str | None = None


class PrekeyService:
    """
    Manages publication and retrieval of client-generated public prekey bundles
    """
    async def store_client_keys(
        self,
        session: AsyncSession,
        user_id: UUID,
        identity_key: str,
        identity_key_ed25519: str,
        signed_prekey: str,
        signed_prekey_signature: str,
        one_time_prekeys: list[str]
    ) -> IdentityKey:
        """
        Stores client generated public keys for E2E encryption
        """
        statement = select(User).where(User.id == user_id)
        result = await session.execute(statement)
        user = result.scalar_one_or_none()

        if not user:
            logger.error("User not found: %s", user_id)
            raise UserNotFoundError("User not found")

        existing_ik_statement = select(IdentityKey).where(
            IdentityKey.user_id == user_id
        )
        existing_ik_result = await session.execute(existing_ik_statement)
        existing_ik = existing_ik_result.scalar_one_or_none()

        if existing_ik:
            existing_ik.public_key = identity_key
            existing_ik.public_key_ed25519 = identity_key_ed25519
            logger.info("Updated identity key for user %s", user_id)
        else:
            existing_ik = IdentityKey(
                user_id = user_id,
                public_key = identity_key,
                public_key_ed25519 = identity_key_ed25519
            )
            session.add(existing_ik)
            logger.info("Created identity key for user %s", user_id)

        old_spks_statement = select(SignedPrekey).where(
            SignedPrekey.user_id == user_id,
            SignedPrekey.is_active
        )
        old_spks_result = await session.execute(old_spks_statement)
        old_spks = old_spks_result.scalars().all()

        for old_spk in old_spks:
            old_spk.is_active = False

        max_key_id_statement = select(SignedPrekey.key_id).where(
            SignedPrekey.user_id == user_id
        ).order_by(SignedPrekey.key_id.desc()).limit(1)
        max_key_id_result = await session.execute(max_key_id_statement)
        max_key_id = max_key_id_result.scalar_one_or_none()
        new_spk_key_id = (max_key_id + 1) if max_key_id is not None else 1

        expires_at = datetime.now(UTC) + timedelta(hours = SIGNED_PREKEY_ROTATION_HOURS)

        new_spk = SignedPrekey(
            user_id = user_id,
            key_id = new_spk_key_id,
            public_key = signed_prekey,
            signature = signed_prekey_signature,
            is_active = True,
            expires_at = expires_at
        )
        session.add(new_spk)

        max_opk_key_id_statement = select(OneTimePrekey.key_id).where(
            OneTimePrekey.user_id == user_id
        ).order_by(OneTimePrekey.key_id.desc()).limit(1)
        max_opk_key_id_result = await session.execute(max_opk_key_id_statement)
        max_opk_key_id = max_opk_key_id_result.scalar_one_or_none()
        next_opk_key_id = (max_opk_key_id + 1) if max_opk_key_id is not None else 1

        for i, opk_public in enumerate(one_time_prekeys):
            new_opk = OneTimePrekey(
                user_id = user_id,
                key_id = next_opk_key_id + i,
                public_key = opk_public,
                is_used = False
            )
            session.add(new_opk)

        try:
            await session.commit()
            await session.refresh(existing_ik)
            logger.info(
                "Stored client keys for user %s: IK + SPK + %s OPKs",
                user_id,
                len(one_time_prekeys)
            )
        except IntegrityError as e:
            await session.rollback()
            logger.error("Database error storing client keys: %s", e)
            raise DatabaseError("Failed to store client keys") from e

        return existing_ik

    async def get_prekey_bundle(
        self,
        session: AsyncSession,
        user_id: UUID
    ) -> PreKeyBundle:
        """
        Retrieves prekey bundle for initiating X3DH key exchange
        """
        ik_statement = select(IdentityKey).where(IdentityKey.user_id == user_id)
        ik_result = await session.execute(ik_statement)
        identity_key = ik_result.scalar_one_or_none()

        if not identity_key:
            logger.error("Identity key not found for user %s", user_id)
            raise InvalidDataError("User has not uploaded keys yet")

        spk_statement = select(SignedPrekey).where(
            SignedPrekey.user_id == user_id,
            SignedPrekey.is_active
        ).order_by(SignedPrekey.created_at.desc())
        spk_result = await session.execute(spk_statement)
        signed_prekey = spk_result.scalar_one_or_none()

        if not signed_prekey:
            raise InvalidDataError("User has no active signed prekey")

        opk_statement = select(OneTimePrekey).where(
            OneTimePrekey.user_id == user_id,
            OneTimePrekey.is_used.is_(False)
        ).limit(1)
        opk_result = await session.execute(opk_statement)
        one_time_prekey = opk_result.scalar_one_or_none()

        one_time_prekey_public = None
        if one_time_prekey:
            one_time_prekey.is_used = True
            one_time_prekey_public = one_time_prekey.public_key
            logger.debug(
                "Consumed one time prekey %s for user %s",
                one_time_prekey.key_id,
                user_id
            )

            try:
                await session.commit()
            except IntegrityError as e:
                await session.rollback()
                logger.error("Database error consuming OPK: %s", e)
                raise DatabaseError("Failed to consume one-time prekey") from e

        bundle = PreKeyBundle(
            identity_key = identity_key.public_key,
            identity_key_ed25519 = identity_key.public_key_ed25519,
            signed_prekey = signed_prekey.public_key,
            signed_prekey_signature = signed_prekey.signature,
            one_time_prekey = one_time_prekey_public
        )

        logger.info(
            "Retrieved prekey bundle for user %s (OPK: %s)",
            user_id,
            'yes' if one_time_prekey_public else 'no'
        )

        return bundle


prekey_service = PrekeyService()
