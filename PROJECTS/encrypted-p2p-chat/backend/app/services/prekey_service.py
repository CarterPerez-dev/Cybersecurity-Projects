"""
ⒸAngelaMos | 2025
Prekey management service for X3DH key bundles
"""

import logging
from datetime import (
    UTC,
    datetime,
    timedelta,
)
from uuid import UUID

from sqlmodel import select
from sqlalchemy.exc import IntegrityError
from sqlmodel.ext.asyncio.session import AsyncSession

from app.config import (
    DEFAULT_ONE_TIME_PREKEY_COUNT,
    SIGNED_PREKEY_RETENTION_DAYS,
    SIGNED_PREKEY_ROTATION_HOURS,
)
from app.core.encryption.x3dh_manager import (
    PreKeyBundle,
    x3dh_manager,
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


class PrekeyService:
    """
    Service for managing X3DH prekey bundles and key rotation
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
        Stores client-generated public keys for E2E encryption.
        Only stores PUBLIC keys - private keys remain on client.
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
            logger.info("Updated existing identity key for user %s", user_id)
        else:
            existing_ik = IdentityKey(
                user_id = user_id,
                public_key = identity_key,
                private_key = "",
                public_key_ed25519 = identity_key_ed25519,
                private_key_ed25519 = ""
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

        expires_at = datetime.now(UTC) + timedelta(
            hours = SIGNED_PREKEY_ROTATION_HOURS
        )

        new_spk = SignedPrekey(
            user_id = user_id,
            key_id = new_spk_key_id,
            public_key = signed_prekey,
            private_key = "",
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
                private_key = "",
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

    async def initialize_user_keys(
        self,
        session: AsyncSession,
        user_id: UUID
    ) -> IdentityKey:
        """
        Generates and stores initial identity key, 
        signed prekey, and one time prekeys for a user
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
            logger.warning("Identity key already exists for user %s", user_id)
            return existing_ik

        ik_private_x25519, ik_public_x25519 = (
            x3dh_manager.generate_identity_keypair_x25519()
        )
        ik_private_ed25519, ik_public_ed25519 = (
            x3dh_manager.generate_identity_keypair_ed25519()
        )

        identity_key = IdentityKey(
            user_id = user_id,
            public_key = ik_public_x25519,
            private_key = ik_private_x25519,
            public_key_ed25519 = ik_public_ed25519,
            private_key_ed25519 = ik_private_ed25519
        )

        session.add(identity_key)

        try:
            await session.commit()
            await session.refresh(identity_key)
            logger.info("Created identity key for user %s", user_id)
        except IntegrityError as e:
            await session.rollback()
            logger.error("Database error creating identity key: %s", e)
            raise DatabaseError("Failed to create identity key") from e

        await self.rotate_signed_prekey(session, user_id)

        await self.replenish_one_time_prekeys(
            session,
            user_id,
            DEFAULT_ONE_TIME_PREKEY_COUNT
        )

        logger.info(
            "Initialized all keys for user %s: IK + SPK + %s OPKs",
            user_id,
            DEFAULT_ONE_TIME_PREKEY_COUNT
        )

        return identity_key

    async def rotate_signed_prekey(
        self,
        session: AsyncSession,
        user_id: UUID
    ) -> SignedPrekey:
        """
        Generates new signed prekey and marks old ones inactive
        """
        ik_statement = select(IdentityKey).where(IdentityKey.user_id == user_id)
        ik_result = await session.execute(ik_statement)
        identity_key = ik_result.scalar_one_or_none()

        if not identity_key:
            logger.error("Identity key not found for user %s", user_id)
            raise InvalidDataError("User has no identity key")

        old_spks_statement = select(SignedPrekey).where(
            SignedPrekey.user_id == user_id,
            SignedPrekey.is_active
        )
        old_spks_result = await session.execute(old_spks_statement)
        old_spks = old_spks_result.scalars().all()

        for old_spk in old_spks:
            old_spk.is_active = False
            logger.debug("Marked SPK %s as inactive", old_spk.key_id)

        max_key_id_statement = select(SignedPrekey.key_id).where(
            SignedPrekey.user_id == user_id
        ).order_by(SignedPrekey.key_id.desc()).limit(1)
        max_key_id_result = await session.execute(max_key_id_statement)
        max_key_id = max_key_id_result.scalar_one_or_none()
        new_key_id = (max_key_id + 1) if max_key_id is not None else 1

        spk_private, spk_public, spk_signature = (
            x3dh_manager.generate_signed_prekey(
                identity_key.private_key_ed25519
            )
        )

        expires_at = datetime.now(UTC) + timedelta(
            hours = SIGNED_PREKEY_ROTATION_HOURS
        )

        signed_prekey = SignedPrekey(
            user_id = user_id,
            key_id = new_key_id,
            public_key = spk_public,
            private_key = spk_private,
            signature = spk_signature,
            is_active = True,
            expires_at = expires_at
        )

        session.add(signed_prekey)

        try:
            await session.commit()
            await session.refresh(signed_prekey)
            logger.info(
                "Rotated signed prekey for user %s: key_id=%s, expires=%s",
                user_id,
                new_key_id,
                expires_at
            )
        except IntegrityError as e:
            await session.rollback()
            logger.error("Database error rotating signed prekey: %s", e)
            raise DatabaseError("Failed to rotate signed prekey") from e

        return signed_prekey

    async def get_prekey_bundle(
        self,
        session: AsyncSession,
        user_id: UUID
    ) -> PreKeyBundle:
        """
        Retrieves prekey bundle for initiating X3DH with a user
        """
        ik_statement = select(IdentityKey).where(IdentityKey.user_id == user_id)
        ik_result = await session.execute(ik_statement)
        identity_key = ik_result.scalar_one_or_none()

        if not identity_key:
            logger.error("Identity key not found for user %s", user_id)
            raise InvalidDataError("User has no identity key")

        spk_statement = select(SignedPrekey).where(
            SignedPrekey.user_id == user_id,
            SignedPrekey.is_active
        ).order_by(SignedPrekey.created_at.desc())
        spk_result = await session.execute(spk_statement)
        signed_prekey = spk_result.scalar_one_or_none()

        if not signed_prekey:
            logger.warning(
                "No active signed prekey for user %s, rotating",
                user_id
            )
            signed_prekey = await self.rotate_signed_prekey(session, user_id)

        opk_statement = select(OneTimePrekey).where(
            OneTimePrekey.user_id == user_id,
            not OneTimePrekey.is_used
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
            "Retrieved prekey bundle for user %s: IK + SPK + %s",
            user_id,
            'OPK' if one_time_prekey_public else 'no OPK'
        )

        return bundle

    async def replenish_one_time_prekeys(
        self,
        session: AsyncSession,
        user_id: UUID,
        count: int = DEFAULT_ONE_TIME_PREKEY_COUNT
    ) -> int:
        """
        Generates new batch of one time prekeys
        """
        max_key_id_statement = select(OneTimePrekey.key_id).where(
            OneTimePrekey.user_id == user_id
        ).order_by(OneTimePrekey.key_id.desc()).limit(1)
        max_key_id_result = await session.execute(max_key_id_statement)
        max_key_id = max_key_id_result.scalar_one_or_none()
        next_key_id = (max_key_id + 1) if max_key_id is not None else 1

        one_time_prekeys = []
        for i in range(count):
            opk_private, opk_public = x3dh_manager.generate_one_time_prekey()

            one_time_prekey = OneTimePrekey(
                user_id = user_id,
                key_id = next_key_id + i,
                public_key = opk_public,
                private_key = opk_private,
                is_used = False
            )
            one_time_prekeys.append(one_time_prekey)

        for opk in one_time_prekeys:
            session.add(opk)

        try:
            await session.commit()
            logger.info(
                "Generated %s one-time prekeys for user %s",
                count,
                user_id
            )
        except IntegrityError as e:
            await session.rollback()
            logger.error("Database error generating OPKs: %s", e)
            raise DatabaseError("Failed to generate one-time prekeys") from e

        return count

    async def get_unused_opk_count(
        self,
        session: AsyncSession,
        user_id: UUID
    ) -> int:
        """
        Returns count of unused one time prekeys for a user
        """
        count_statement = select(OneTimePrekey).where(
            OneTimePrekey.user_id == user_id,
            not OneTimePrekey.is_used
        )
        result = await session.execute(count_statement)
        unused_opks = result.scalars().all()

        count = len(unused_opks)
        logger.debug("User %s has %s unused OPKs", user_id, count)
        return count

    async def cleanup_old_signed_prekeys(
        self,
        session: AsyncSession,
        user_id: UUID
    ) -> int:
        """
        Deletes inactive signed prekeys older than retention period
        """
        cutoff_date = datetime.now(UTC) - timedelta(
            days = SIGNED_PREKEY_RETENTION_DAYS
        )

        old_spks_statement = select(SignedPrekey).where(
            SignedPrekey.user_id == user_id,
            not SignedPrekey.is_active,
            SignedPrekey.created_at < cutoff_date
        )
        old_spks_result = await session.execute(old_spks_statement)
        old_spks = old_spks_result.scalars().all()

        deleted_count = len(old_spks)

        for spk in old_spks:
            await session.delete(spk)

        try:
            await session.commit()
            logger.info(
                "Deleted %s old signed prekeys for user %s",
                deleted_count,
                user_id
            )
        except IntegrityError as e:
            await session.rollback()
            logger.error("Database error deleting old SPKs: %s", e)
            raise DatabaseError("Failed to delete old signed prekeys") from e

        return deleted_count


prekey_service = PrekeyService()
