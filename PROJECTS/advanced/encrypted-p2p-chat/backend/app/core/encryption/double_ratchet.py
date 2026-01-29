"""
ⒸAngelaMos | 2025
Double Ratchet algorithm implementation for end to end encryption
"""

import os
import logging
from dataclasses import (
    field,
    dataclass,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization

from app.config import (
    AES_GCM_NONCE_SIZE,
    HKDF_OUTPUT_SIZE,
    MAX_CACHED_MESSAGE_KEYS,
    MAX_SKIP_MESSAGE_KEYS,
    X25519_KEY_SIZE,
)


logger = logging.getLogger(__name__)


@dataclass
class DoubleRatchetState:
    """
    Complete state for Double Ratchet algorithm per conversation
    """
    root_key: bytes
    sending_chain_key: bytes
    receiving_chain_key: bytes
    dh_private_key: X25519PrivateKey | None
    dh_peer_public_key: bytes | None
    sending_message_number: int = 0
    receiving_message_number: int = 0
    previous_sending_chain_length: int = 0
    skipped_message_keys: dict[tuple[bytes,
                                     int],
                               bytes] = field(default_factory = dict)


@dataclass
class EncryptedMessage:
    """
    Encrypted message with header and metadata
    """
    ciphertext: bytes
    nonce: bytes
    dh_public_key: bytes
    message_number: int
    previous_chain_length: int


class DoubleRatchet:
    """
    Implementation of Signal Protocol Double Ratchet algorithm
    """
    def __init__(
        self,
        max_skip: int = MAX_SKIP_MESSAGE_KEYS,
        max_cache: int = MAX_CACHED_MESSAGE_KEYS
    ):
        """
        Initialize Double Ratchet with security limits
        """
        self.max_skip = max_skip
        self.max_cache = max_cache

    def _kdf_rk(self, root_key: bytes, dh_output: bytes) -> tuple[bytes, bytes]:
        """
        Derives new root key and chain key from DH output
        """
        hkdf = HKDF(
            algorithm = hashes.SHA256(),
            length = HKDF_OUTPUT_SIZE * 2,
            salt = root_key,
            info = b'',
        )
        output = hkdf.derive(dh_output)
        new_root_key = output[: HKDF_OUTPUT_SIZE]
        new_chain_key = output[HKDF_OUTPUT_SIZE :]

        logger.debug("Derived new root key and chain key")
        return new_root_key, new_chain_key

    def _kdf_ck(self, chain_key: bytes) -> tuple[bytes, bytes]:
        """
        Derives next chain key and message key from current chain key
        """
        h_chain = hmac.HMAC(chain_key, hashes.SHA256())
        h_chain.update(b'\x01')
        next_chain_key = h_chain.finalize()

        h_message = hmac.HMAC(chain_key, hashes.SHA256())
        h_message.update(b'\x02')
        message_key = h_message.finalize()

        logger.debug("Derived next chain key and message key")
        return next_chain_key, message_key

    def _encrypt_with_message_key(
        self,
        message_key: bytes,
        plaintext: bytes,
        associated_data: bytes
    ) -> tuple[bytes,
               bytes]:
        """
        Encrypts plaintext using AES-256-GCM with message key
        """
        aesgcm = AESGCM(message_key)
        nonce = os.urandom(AES_GCM_NONCE_SIZE)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)

        logger.debug(
            "Encrypted %s bytes to %s bytes",
            len(plaintext),
            len(ciphertext)
        )
        return nonce, ciphertext

    def _decrypt_with_message_key(
        self,
        message_key: bytes,
        nonce: bytes,
        ciphertext: bytes,
        associated_data: bytes
    ) -> bytes:
        """
        Decrypts ciphertext using AES-256-GCM with message key
        """
        aesgcm = AESGCM(message_key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
            logger.debug(
                "Decrypted %s bytes to %s bytes",
                len(ciphertext),
                len(plaintext)
            )
            return plaintext
        except InvalidTag as e:
            logger.error("Message authentication failed")
            raise ValueError("Message tampered or corrupted") from e

    def _dh_ratchet_send(self, state: DoubleRatchetState) -> None:
        """
        Performs DH ratchet step when sending
        """
        state.dh_private_key = X25519PrivateKey.generate()

        state.previous_sending_chain_length = state.sending_message_number
        state.sending_message_number = 0
        state.receiving_message_number = 0

        if state.dh_peer_public_key:
            peer_public = X25519PublicKey.from_public_bytes(
                state.dh_peer_public_key
            )
            dh_output = state.dh_private_key.exchange(peer_public)

            state.root_key, state.sending_chain_key = self._kdf_rk(
                state.root_key,
                dh_output
            )

        logger.debug("DH ratchet step completed (send)")

    def _dh_ratchet_receive(
        self,
        state: DoubleRatchetState,
        peer_public_key: bytes
    ) -> None:
        """
        Performs DH ratchet step when receiving
        """
        state.previous_sending_chain_length = state.sending_message_number
        state.sending_message_number = 0
        state.receiving_message_number = 0
        state.dh_peer_public_key = peer_public_key

        if state.dh_private_key:
            peer_public = X25519PublicKey.from_public_bytes(peer_public_key)
            dh_output = state.dh_private_key.exchange(peer_public)

            state.root_key, state.receiving_chain_key = self._kdf_rk(
                state.root_key,
                dh_output
            )

        state.dh_private_key = X25519PrivateKey.generate()

        if state.dh_peer_public_key:
            peer_public = X25519PublicKey.from_public_bytes(
                state.dh_peer_public_key
            )
            dh_output = state.dh_private_key.exchange(peer_public)

            state.root_key, state.sending_chain_key = self._kdf_rk(
                state.root_key,
                dh_output
            )

        logger.debug("DH ratchet step completed (receive)")

    def _store_skipped_message_keys(
        self,
        state: DoubleRatchetState,
        until_message_number: int,
        dh_public_key: bytes
    ) -> None:
        """
        Stores skipped message keys for out of order delivery
        """
        num_to_skip = until_message_number - state.receiving_message_number

        if num_to_skip > self.max_skip:
            raise ValueError(
                f"Cannot skip {num_to_skip} messages "
                f"(MAX_SKIP={self.max_skip})"
            )

        if len(state.skipped_message_keys) + num_to_skip > self.max_cache:
            logger.warning("Skipped message key cache full, evicting oldest keys")
            self._evict_oldest_skipped_keys(state, num_to_skip)

        chain_key = state.receiving_chain_key
        for msg_num in range(state.receiving_message_number,
                             until_message_number):
            chain_key, message_key = self._kdf_ck(chain_key)
            state.skipped_message_keys[(dh_public_key, msg_num)] = message_key

        state.receiving_chain_key = chain_key

        logger.debug("Stored %s skipped message keys", num_to_skip)

    def _evict_oldest_skipped_keys(
        self,
        state: DoubleRatchetState,
        count: int
    ) -> None:
        """
        Evicts oldest skipped message keys to make room
        """
        keys_to_remove = list(state.skipped_message_keys.keys())[: count]
        for key in keys_to_remove:
            del state.skipped_message_keys[key]

        logger.debug("Evicted %s skipped keys", len(keys_to_remove))

    def _try_skipped_message_key(
        self,
        state: DoubleRatchetState,
        dh_public_key: bytes,
        message_number: int
    ) -> bytes | None:
        """
        Attempts to retrieve skipped message key
        """
        key = (dh_public_key, message_number)
        message_key = state.skipped_message_keys.pop(key, None)

        if message_key:
            logger.debug(
                "Retrieved skipped message key for msg %s",
                message_number
            )
        return message_key

    def initialize_sender(
        self,
        shared_key: bytes,
        peer_public_key: bytes
    ) -> DoubleRatchetState:
        """
        Initializes Double Ratchet as sender after X3DH
        """
        dh_private = X25519PrivateKey.generate()
        peer_public = X25519PublicKey.from_public_bytes(peer_public_key)
        dh_output = dh_private.exchange(peer_public)

        root_key, sending_chain_key = self._kdf_rk(shared_key, dh_output)

        state = DoubleRatchetState(
            root_key = root_key,
            sending_chain_key = sending_chain_key,
            receiving_chain_key = b'\x00' * HKDF_OUTPUT_SIZE,
            dh_private_key = dh_private,
            dh_peer_public_key = peer_public_key
        )

        logger.info("Double Ratchet initialized as sender")
        return state

    def initialize_receiver(
        self,
        shared_key: bytes,
        own_private_key: X25519PrivateKey
    ) -> DoubleRatchetState:
        """
        Initializes Double Ratchet as receiver after X3DH
        """
        state = DoubleRatchetState(
            root_key = shared_key,
            sending_chain_key = b'\x00' * HKDF_OUTPUT_SIZE,
            receiving_chain_key = b'\x00' * HKDF_OUTPUT_SIZE,
            dh_private_key = own_private_key,
            dh_peer_public_key = None
        )

        logger.info("Double Ratchet initialized as receiver")
        return state

    def encrypt_message(
        self,
        state: DoubleRatchetState,
        plaintext: bytes,
        associated_data: bytes
    ) -> EncryptedMessage:
        """
        Encrypts message and advances sending ratchet
        """
        state.sending_chain_key, message_key = self._kdf_ck(
            state.sending_chain_key
        )

        nonce, ciphertext = self._encrypt_with_message_key(
            message_key,
            plaintext,
            associated_data
        )

        if state.dh_private_key:
            dh_public = state.dh_private_key.public_key()
            dh_public_bytes = dh_public.public_bytes(
                encoding = serialization.Encoding.Raw,
                format = serialization.PublicFormat.Raw
            )
        else:
            dh_public_bytes = b'\x00' * X25519_KEY_SIZE

        encrypted_msg = EncryptedMessage(
            ciphertext = ciphertext,
            nonce = nonce,
            dh_public_key = dh_public_bytes,
            message_number = state.sending_message_number,
            previous_chain_length = state.previous_sending_chain_length
        )

        state.sending_message_number += 1

        logger.info("Encrypted message #%s", encrypted_msg.message_number)
        return encrypted_msg

    def decrypt_message(
        self,
        state: DoubleRatchetState,
        encrypted_msg: EncryptedMessage,
        associated_data: bytes
    ) -> bytes:
        """
        Decrypts message and advances receiving ratchet
        """
        skipped_key = self._try_skipped_message_key(
            state,
            encrypted_msg.dh_public_key,
            encrypted_msg.message_number
        )
        if skipped_key:
            return self._decrypt_with_message_key(
                skipped_key,
                encrypted_msg.nonce,
                encrypted_msg.ciphertext,
                associated_data
            )

        if encrypted_msg.dh_public_key != state.dh_peer_public_key:
            if state.dh_peer_public_key:
                self._store_skipped_message_keys(
                    state,
                    encrypted_msg.previous_chain_length,
                    state.dh_peer_public_key
                )

            self._dh_ratchet_receive(state, encrypted_msg.dh_public_key)

        if encrypted_msg.message_number > state.receiving_message_number:
            self._store_skipped_message_keys(
                state,
                encrypted_msg.message_number,
                encrypted_msg.dh_public_key
            )

        state.receiving_chain_key, message_key = self._kdf_ck(
            state.receiving_chain_key
        )
        state.receiving_message_number += 1

        plaintext = self._decrypt_with_message_key(
            message_key,
            encrypted_msg.nonce,
            encrypted_msg.ciphertext,
            associated_data
        )

        logger.info("Decrypted message #%s", encrypted_msg.message_number)
        return plaintext


double_ratchet = DoubleRatchet()
