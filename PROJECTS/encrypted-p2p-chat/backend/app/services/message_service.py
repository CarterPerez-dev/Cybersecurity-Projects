"""
ⒸAngelaMos | 2025
Message service with end-to-end encryption using Double Ratchet
"""

import json
import logging
from typing import Any
from uuid import UUID

from sqlmodel import select
from sqlalchemy.exc import IntegrityError
from sqlmodel.ext.asyncio.session import AsyncSession
from cryptography.hazmat.primitives import serialization
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
)
from app.core.encryption.double_ratchet import (
    DoubleRatchetState,
    EncryptedMessage,
    double_ratchet,
)
from app.core.encryption.x3dh_manager import x3dh_manager
from app.core.exceptions import (
    DatabaseError,
    DecryptionError,
    EncryptionError,
    InvalidDataError,
    KeyExchangeError,
    RatchetStateNotFoundError,
    UserNotFoundError,
)
from app.core.surreal_manager import surreal_db
from app.models.IdentityKey import IdentityKey
from app.models.RatchetState import RatchetState
from app.models.User import User
from app.services.prekey_service import prekey_service


logger = logging.getLogger(__name__)


class MessageService:
    """
    Service for encrypted messaging using Double Ratchet protocol
    """
    async def initialize_conversation(
        self,
        session: AsyncSession,
        sender_id: UUID,
        recipient_id: UUID
    ) -> RatchetState:
        """
        Performs X3DH key exchange and initializes Double Ratchet for new conversation
        """
        if sender_id == recipient_id:
            raise InvalidDataError("Cannot start conversation with yourself")

        existing_state_statement = select(RatchetState).where(
            RatchetState.user_id == sender_id,
            RatchetState.peer_user_id == recipient_id
        )
        existing_state_result = await session.execute(existing_state_statement)
        existing_state = existing_state_result.scalar_one_or_none()

        if existing_state:
            logger.warning(
                "Ratchet state already exists for %s -> %s",
                sender_id,
                recipient_id
            )
            return existing_state

        sender_ik_statement = select(IdentityKey).where(
            IdentityKey.user_id == sender_id
        )
        sender_ik_result = await session.execute(sender_ik_statement)
        sender_ik = sender_ik_result.scalar_one_or_none()

        if not sender_ik:
            logger.error("Sender identity key not found: %s", sender_id)
            raise InvalidDataError(
                "Sender has no identity key - initialize encryption first"
            )

        recipient_bundle = await prekey_service.get_prekey_bundle(
            session,
            recipient_id
        )

        recipient_ik_statement = select(IdentityKey).where(
            IdentityKey.user_id == recipient_id
        )
        recipient_ik_result = await session.execute(recipient_ik_statement)
        recipient_ik = recipient_ik_result.scalar_one_or_none()

        if not recipient_ik:
            logger.error("Recipient identity key not found: %s", recipient_id)
            raise InvalidDataError("Recipient has no identity key")

        try:
            x3dh_result = x3dh_manager.perform_x3dh_sender(
                alice_identity_private_x25519 = sender_ik.private_key,
                bob_bundle = recipient_bundle,
                bob_identity_public_ed25519 = recipient_ik.public_key_ed25519
            )
        except Exception as e:
            logger.error("X3DH key exchange failed: %s", e)
            raise KeyExchangeError(f"Key exchange failed: {str(e)}") from e

        recipient_spk_public_bytes = base64url_to_bytes(
            recipient_bundle.signed_prekey
        )

        dr_state = double_ratchet.initialize_sender(
            shared_key = x3dh_result.shared_key,
            peer_public_key = recipient_spk_public_bytes
        )

        dh_private_bytes = dr_state.dh_private_key.private_bytes(
            encoding = serialization.Encoding.Raw,
            format = serialization.PrivateFormat.Raw,
            encryption_algorithm = serialization.NoEncryption()
        ) if dr_state.dh_private_key else b''

        dh_public_bytes = dr_state.dh_private_key.public_key().public_bytes(
            encoding = serialization.Encoding.Raw,
            format = serialization.PublicFormat.Raw
        ) if dr_state.dh_private_key else b''

        ratchet_state = RatchetState(
            user_id = sender_id,
            peer_user_id = recipient_id,
            dh_private_key = bytes_to_base64url(dh_private_bytes),
            dh_public_key = bytes_to_base64url(dh_public_bytes),
            dh_peer_public_key = bytes_to_base64url(dr_state.dh_peer_public_key)
            if dr_state.dh_peer_public_key else None,
            root_key = bytes_to_base64url(dr_state.root_key),
            sending_chain_key = bytes_to_base64url(dr_state.sending_chain_key),
            receiving_chain_key = bytes_to_base64url(
                dr_state.receiving_chain_key
            ),
            sending_message_number = dr_state.sending_message_number,
            receiving_message_number = dr_state.receiving_message_number,
            previous_sending_chain_length = (
                dr_state.previous_sending_chain_length
            )
        )

        session.add(ratchet_state)

        try:
            await session.commit()
            await session.refresh(ratchet_state)
            logger.info(
                "Initialized conversation: %s -> %s (X3DH complete)",
                sender_id,
                recipient_id
            )
        except IntegrityError as e:
            await session.rollback()
            logger.error("Database error saving ratchet state: %s", e)
            raise DatabaseError("Failed to initialize conversation") from e

        return ratchet_state

    async def _load_ratchet_state_from_db(
        self,
        ratchet_state_db: RatchetState
    ) -> DoubleRatchetState:
        """
        Converts database RatchetState to DoubleRatchetState object
        """
        dh_private_key = None
        if ratchet_state_db.dh_private_key:
            dh_private_bytes = base64url_to_bytes(ratchet_state_db.dh_private_key)
            dh_private_key = X25519PrivateKey.from_private_bytes(dh_private_bytes)

        dh_peer_public_key = None
        if ratchet_state_db.dh_peer_public_key:
            dh_peer_public_key = base64url_to_bytes(
                ratchet_state_db.dh_peer_public_key
            )

        root_key = base64url_to_bytes(ratchet_state_db.root_key)
        sending_chain_key = base64url_to_bytes(ratchet_state_db.sending_chain_key)
        receiving_chain_key = base64url_to_bytes(
            ratchet_state_db.receiving_chain_key
        )

        return DoubleRatchetState(
            root_key = root_key,
            sending_chain_key = sending_chain_key,
            receiving_chain_key = receiving_chain_key,
            dh_private_key = dh_private_key,
            dh_peer_public_key = dh_peer_public_key,
            sending_message_number = ratchet_state_db.sending_message_number,
            receiving_message_number = (
                ratchet_state_db.receiving_message_number
            ),
            previous_sending_chain_length = (
                ratchet_state_db.previous_sending_chain_length
            ),
            skipped_message_keys = {}
        )

    async def _save_ratchet_state_to_db(
        self,
        session: AsyncSession,
        ratchet_state_db: RatchetState,
        dr_state: DoubleRatchetState
    ) -> None:
        """
        Updates database RatchetState from DoubleRatchetState object
        """
        if dr_state.dh_private_key:
            dh_private_bytes = dr_state.dh_private_key.private_bytes(
                encoding = serialization.Encoding.Raw,
                format = serialization.PrivateFormat.Raw,
                encryption_algorithm = serialization.NoEncryption()
            )
            dh_public_bytes = dr_state.dh_private_key.public_key().public_bytes(
                encoding = serialization.Encoding.Raw,
                format = serialization.PublicFormat.Raw
            )
            ratchet_state_db.dh_private_key = bytes_to_base64url(dh_private_bytes)
            ratchet_state_db.dh_public_key = bytes_to_base64url(dh_public_bytes)
        else:
            ratchet_state_db.dh_private_key = None
            ratchet_state_db.dh_public_key = None

        if dr_state.dh_peer_public_key:
            ratchet_state_db.dh_peer_public_key = bytes_to_base64url(
                dr_state.dh_peer_public_key
            )
        else:
            ratchet_state_db.dh_peer_public_key = None

        ratchet_state_db.root_key = bytes_to_base64url(dr_state.root_key)
        ratchet_state_db.sending_chain_key = bytes_to_base64url(
            dr_state.sending_chain_key
        )
        ratchet_state_db.receiving_chain_key = bytes_to_base64url(
            dr_state.receiving_chain_key
        )
        ratchet_state_db.sending_message_number = (
            dr_state.sending_message_number
        )
        ratchet_state_db.receiving_message_number = (
            dr_state.receiving_message_number
        )
        ratchet_state_db.previous_sending_chain_length = (
            dr_state.previous_sending_chain_length
        )

        try:
            await session.commit()
            logger.debug(
                "Saved ratchet state: send=%s, recv=%s",
                dr_state.sending_message_number,
                dr_state.receiving_message_number
            )
        except IntegrityError as e:
            await session.rollback()
            logger.error("Database error saving ratchet state: %s", e)
            raise DatabaseError("Failed to save ratchet state") from e

    async def store_encrypted_message(
        self,
        session: AsyncSession,
        sender_id: UUID,
        recipient_id: UUID,
        ciphertext: str,
        nonce: str,
        header: str,
        room_id: str | None = None,
    ) -> Any:
        """
        Stores client-encrypted message in SurrealDB (pass-through, no server encryption)
        """
        sender_user_statement = select(User).where(User.id == sender_id)
        sender_user_result = await session.execute(sender_user_statement)
        sender_user = sender_user_result.scalar_one_or_none()

        if not sender_user:
            raise UserNotFoundError("Sender not found")

        from datetime import UTC, datetime

        now = datetime.now(UTC)
        surreal_message = {
            "sender_id": str(sender_id),
            "recipient_id": str(recipient_id),
            "room_id": room_id,
            "ciphertext": ciphertext,
            "nonce": nonce,
            "header": header,
            "sender_username": sender_user.username,
            "created_at": now.isoformat(),
            "updated_at": now.isoformat(),
        }

        try:
            result = await surreal_db.create_message(surreal_message)
            logger.info(
                "Stored client-encrypted message: %s -> %s",
                sender_id,
                recipient_id
            )
            return result
        except Exception as e:
            logger.error("Failed to store encrypted message: %s", e)
            raise DatabaseError(f"Failed to store message: {str(e)}") from e

    async def send_encrypted_message(
        self,
        session: AsyncSession,
        sender_id: UUID,
        recipient_id: UUID,
        plaintext: str,
        room_id: str | None = None,
    ) -> Any:
        """
        [DEPRECATED] Server-side encryption - kept for backwards compatibility
        Encrypts message with Double Ratchet and stores in SurrealDB
        """
        ratchet_state_statement = select(RatchetState).where(
            RatchetState.user_id == sender_id,
            RatchetState.peer_user_id == recipient_id
        )
        ratchet_state_result = await session.execute(ratchet_state_statement)
        ratchet_state_db = ratchet_state_result.scalar_one_or_none()

        if not ratchet_state_db:
            logger.warning(
                "No ratchet state for %s -> %s, initializing",
                sender_id,
                recipient_id
            )
            ratchet_state_db = await self.initialize_conversation(
                session,
                sender_id,
                recipient_id
            )

        dr_state = await self._load_ratchet_state_from_db(ratchet_state_db)

        sender_user_statement = select(User).where(User.id == sender_id)
        sender_user_result = await session.execute(sender_user_statement)
        sender_user = sender_user_result.scalar_one_or_none()

        if not sender_user:
            raise UserNotFoundError("Sender not found")

        associated_data = f"{sender_id}:{recipient_id}".encode()

        try:
            encrypted_msg = double_ratchet.encrypt_message(
                dr_state,
                plaintext.encode(),
                associated_data
            )
        except Exception as e:
            logger.error("Encryption failed: %s", e)
            raise EncryptionError(f"Failed to encrypt message: {str(e)}") from e

        await self._save_ratchet_state_to_db(session, ratchet_state_db, dr_state)

        message_header = {
            "dh_public_key": bytes_to_base64url(encrypted_msg.dh_public_key),
            "message_number": encrypted_msg.message_number,
            "previous_chain_length": encrypted_msg.previous_chain_length
        }

        from datetime import UTC, datetime

        now = datetime.now(UTC)
        surreal_message = {
            "sender_id": str(sender_id),
            "recipient_id": str(recipient_id),
            "room_id": room_id,
            "ciphertext": bytes_to_base64url(encrypted_msg.ciphertext),
            "nonce": bytes_to_base64url(encrypted_msg.nonce),
            "header": json.dumps(message_header),
            "sender_username": sender_user.username,
            "created_at": now.isoformat(),
            "updated_at": now.isoformat(),
        }

        try:
            result = await surreal_db.create_message(surreal_message)
            logger.info(
                "Sent encrypted message: %s -> %s (msg #%s)",
                sender_id,
                recipient_id,
                encrypted_msg.message_number
            )
            return result
        except Exception as e:
            logger.error("Failed to store encrypted message: %s", e)
            raise DatabaseError(f"Failed to store message: {str(e)}") from e

    async def decrypt_received_message(
        self,
        session: AsyncSession,
        recipient_id: UUID,
        message_data: dict[str,
                           Any]
    ) -> str:
        """
        Decrypts received message using Double Ratchet
        """
        sender_id = UUID(message_data["sender_id"])

        ratchet_state_statement = select(RatchetState).where(
            RatchetState.user_id == recipient_id,
            RatchetState.peer_user_id == sender_id
        )
        ratchet_state_result = await session.execute(ratchet_state_statement)
        ratchet_state_db = ratchet_state_result.scalar_one_or_none()

        if not ratchet_state_db:
            logger.error(
                "No ratchet state for receiving: %s <- %s",
                recipient_id,
                sender_id
            )
            raise RatchetStateNotFoundError("No encryption session with sender")

        dr_state = await self._load_ratchet_state_from_db(ratchet_state_db)

        header = json.loads(message_data["header"])

        encrypted_msg = EncryptedMessage(
            ciphertext = base64url_to_bytes(message_data["ciphertext"]),
            nonce = base64url_to_bytes(message_data["nonce"]),
            dh_public_key = base64url_to_bytes(header["dh_public_key"]),
            message_number = header["message_number"],
            previous_chain_length = header["previous_chain_length"]
        )

        associated_data = f"{sender_id}:{recipient_id}".encode()

        try:
            plaintext_bytes = double_ratchet.decrypt_message(
                dr_state,
                encrypted_msg,
                associated_data
            )
        except Exception as e:
            logger.error("Decryption failed: %s", e)
            raise DecryptionError(f"Failed to decrypt message: {str(e)}") from e

        await self._save_ratchet_state_to_db(session, ratchet_state_db, dr_state)

        plaintext = plaintext_bytes.decode()

        logger.info(
            "Decrypted message: %s <- %s (msg #%s)",
            recipient_id,
            sender_id,
            encrypted_msg.message_number
        )

        return plaintext


message_service = MessageService()
