"""
ⒸAngelaMos | 2025
Tests for message service (end to end encryption flow)
"""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.User import User
from app.models.IdentityKey import IdentityKey
from app.models.SignedPrekey import SignedPrekey
from app.core.exceptions import InvalidDataError
from app.models.OneTimePrekey import OneTimePrekey
from app.services.message_service import message_service
from app.core.encryption.x3dh_manager import x3dh_manager


class TestMessageService:
    """
    Test message encryption/decryption service
    """
    @pytest.mark.asyncio
    async def test_initialize_conversation(
        self,
        db_session: AsyncSession,
        test_user: User,
        test_user_2: User,
        test_identity_key: IdentityKey,
        test_signed_prekey: SignedPrekey,
        test_one_time_prekey: OneTimePrekey
    ):
        """
        Test initializing encrypted conversation between two users
        """
        sender_ik_private, sender_ik_public = (
            x3dh_manager.generate_identity_keypair_x25519()
        )
        sender_ik_private_ed, sender_ik_public_ed = (
            x3dh_manager.generate_identity_keypair_ed25519()
        )

        sender_identity_key = IdentityKey(
            user_id = test_user_2.id,
            public_key = sender_ik_public,
            private_key = sender_ik_private,
            public_key_ed25519 = sender_ik_public_ed,
            private_key_ed25519 = sender_ik_private_ed,
        )
        db_session.add(sender_identity_key)
        await db_session.commit()

        ratchet_state = await message_service.initialize_conversation(
            session = db_session,
            sender_id = test_user_2.id,
            recipient_id = test_user.id
        )

        assert ratchet_state.user_id == test_user_2.id
        assert ratchet_state.peer_user_id == test_user.id
        assert ratchet_state.sending_message_number == 0
        assert ratchet_state.receiving_message_number == 0
        assert ratchet_state.dh_public_key is not None

    @pytest.mark.asyncio
    async def test_cannot_initialize_with_self(
        self,
        db_session: AsyncSession,
        test_user: User
    ):
        """
        Test cannot start conversation with yourself
        """
        with pytest.raises(InvalidDataError,
                           match = "Cannot start conversation with yourself"):
            await message_service.initialize_conversation(
                session = db_session,
                sender_id = test_user.id,
                recipient_id = test_user.id
            )

    @pytest.mark.asyncio
    async def test_ratchet_state_persistence(
        self,
        db_session: AsyncSession,
        test_user: User,
        test_user_2: User,
        test_identity_key: IdentityKey,
        test_signed_prekey: SignedPrekey,
        test_one_time_prekey: OneTimePrekey
    ):
        """
        Test ratchet state loads and saves correctly
        """
        sender_ik_private, sender_ik_public = (
            x3dh_manager.generate_identity_keypair_x25519()
        )
        sender_ik_private_ed, sender_ik_public_ed = (
            x3dh_manager.generate_identity_keypair_ed25519()
        )

        sender_identity_key = IdentityKey(
            user_id = test_user_2.id,
            public_key = sender_ik_public,
            private_key = sender_ik_private,
            public_key_ed25519 = sender_ik_public_ed,
            private_key_ed25519 = sender_ik_private_ed,
        )
        db_session.add(sender_identity_key)
        await db_session.commit()

        ratchet_state = await message_service.initialize_conversation(
            session = db_session,
            sender_id = test_user_2.id,
            recipient_id = test_user.id
        )

        initial_msg_num = ratchet_state.sending_message_number

        dr_state = await message_service._load_ratchet_state_from_db(
            ratchet_state
        )

        assert dr_state.sending_message_number == initial_msg_num
        assert dr_state.dh_private_key is not None

        dr_state.sending_message_number += 1

        await message_service._save_ratchet_state_to_db(
            db_session,
            ratchet_state,
            dr_state
        )

        await db_session.refresh(ratchet_state)
        assert ratchet_state.sending_message_number == initial_msg_num + 1
