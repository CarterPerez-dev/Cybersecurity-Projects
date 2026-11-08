"""
©AngelaMos | 2026
test_prekey_service.py
"""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import InvalidDataError
from app.models.IdentityKey import IdentityKey
from app.models.OneTimePrekey import OneTimePrekey
from app.models.SignedPrekey import SignedPrekey
from app.models.User import User
from app.services.prekey_service import prekey_service


def _seed_identity(user: User) -> IdentityKey:
    """
    Build a fake IdentityKey row for the given user
    """
    return IdentityKey(
        user_id = user.id,
        public_key = "AAAA",
        public_key_ed25519 = "BBBB",
    )


def _seed_signed_prekey(user: User) -> SignedPrekey:
    """
    Build an active signed prekey row for the given user
    """
    return SignedPrekey(
        user_id = user.id,
        key_id = 1,
        public_key = "CCCC",
        signature = "DDDD",
        is_active = True,
    )


class TestPrekeyService:
    """
    Tests for prekey bundle storage and retrieval
    """
    @pytest.mark.asyncio
    async def test_get_prekey_bundle_returns_unused_opk(
        self,
        db_session: AsyncSession,
        test_user: User,
    ) -> None:
        """
        Regression for the broken `not Column` filter that hid every OPK
        """
        db_session.add(_seed_identity(test_user))
        db_session.add(_seed_signed_prekey(test_user))

        for key_id, is_used in enumerate([True, True, False, False, False], 1):
            db_session.add(
                OneTimePrekey(
                    user_id = test_user.id,
                    key_id = key_id,
                    public_key = f"opk{key_id}",
                    is_used = is_used,
                )
            )
        await db_session.commit()

        bundle = await prekey_service.get_prekey_bundle(db_session, test_user.id)
        assert bundle.one_time_prekey is not None
        assert bundle.one_time_prekey.startswith("opk")

    @pytest.mark.asyncio
    async def test_get_prekey_bundle_no_opk_when_all_used(
        self,
        db_session: AsyncSession,
        test_user: User,
    ) -> None:
        """
        Bundle still returns when every OPK is consumed
        """
        db_session.add(_seed_identity(test_user))
        db_session.add(_seed_signed_prekey(test_user))
        db_session.add(
            OneTimePrekey(
                user_id = test_user.id,
                key_id = 1,
                public_key = "opk1",
                is_used = True,
            )
        )
        await db_session.commit()

        bundle = await prekey_service.get_prekey_bundle(db_session, test_user.id)
        assert bundle.one_time_prekey is None

    @pytest.mark.asyncio
    async def test_get_prekey_bundle_requires_identity_key(
        self,
        db_session: AsyncSession,
        test_user: User,
    ) -> None:
        """
        Bundle lookup fails cleanly when keys were never uploaded
        """
        with pytest.raises(InvalidDataError):
            await prekey_service.get_prekey_bundle(db_session, test_user.id)

    @pytest.mark.asyncio
    async def test_store_client_keys_replaces_active_spk(
        self,
        db_session: AsyncSession,
        test_user: User,
    ) -> None:
        """
        Uploading new keys deactivates the previous active SPK
        """
        await prekey_service.store_client_keys(
            db_session,
            test_user.id,
            identity_key = "ik1",
            identity_key_ed25519 = "ik1ed",
            signed_prekey = "spk1",
            signed_prekey_signature = "sig1",
            one_time_prekeys = ["opk1",
                                "opk2"],
        )

        await prekey_service.store_client_keys(
            db_session,
            test_user.id,
            identity_key = "ik2",
            identity_key_ed25519 = "ik2ed",
            signed_prekey = "spk2",
            signed_prekey_signature = "sig2",
            one_time_prekeys = ["opk3"],
        )

        from sqlmodel import select

        active_spks = (
            await db_session.execute(
                select(SignedPrekey).where(
                    SignedPrekey.user_id == test_user.id,
                    SignedPrekey.is_active.is_(True),
                )
            )
        ).scalars().all()
        assert len(active_spks) == 1
        assert active_spks[0].public_key == "spk2"
