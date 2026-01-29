"""
ⒸAngelaMos | 2025
Tests for Double Ratchet encryption core
"""

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from app.core.encryption.double_ratchet import double_ratchet


class TestDoubleRatchet:
    """
    Test Double Ratchet encryption/decryption
    """
    def test_encrypt_decrypt_basic(
        self,
        sample_plaintext: str,
        sample_associated_data: bytes
    ):
        """
        Test basic encrypt/decrypt cycle works
        """
        shared_key = b"0" * 32

        bob_dh_private = X25519PrivateKey.generate()
        bob_dh_public_bytes = bob_dh_private.public_key().public_bytes(
            encoding = serialization.Encoding.Raw,
            format = serialization.PublicFormat.Raw
        )

        sender_state = double_ratchet.initialize_sender(
            shared_key = shared_key,
            peer_public_key = bob_dh_public_bytes
        )

        receiver_state = double_ratchet.initialize_receiver(
            shared_key = shared_key,
            own_private_key = bob_dh_private
        )

        encrypted = double_ratchet.encrypt_message(
            sender_state,
            sample_plaintext.encode(),
            sample_associated_data
        )

        decrypted = double_ratchet.decrypt_message(
            receiver_state,
            encrypted,
            sample_associated_data
        )

        assert decrypted.decode() == sample_plaintext

    def test_multiple_messages(self, sample_associated_data: bytes):
        """
        Test multiple messages maintain state correctly
        """
        shared_key = b"0" * 32

        bob_dh_private = X25519PrivateKey.generate()
        bob_dh_public_bytes = bob_dh_private.public_key().public_bytes(
            encoding = serialization.Encoding.Raw,
            format = serialization.PublicFormat.Raw
        )

        sender_state = double_ratchet.initialize_sender(
            shared_key = shared_key,
            peer_public_key = bob_dh_public_bytes
        )

        receiver_state = double_ratchet.initialize_receiver(
            shared_key = shared_key,
            own_private_key = bob_dh_private
        )

        messages = [b"Message 1", b"Message 2", b"Message 3"]
        encrypted_messages = []

        for msg in messages:
            encrypted = double_ratchet.encrypt_message(
                sender_state,
                msg,
                sample_associated_data
            )
            encrypted_messages.append(encrypted)

        for i, encrypted in enumerate(encrypted_messages):
            decrypted = double_ratchet.decrypt_message(
                receiver_state,
                encrypted,
                sample_associated_data
            )
            assert decrypted == messages[i]

    def test_message_numbers_increment(self, sample_associated_data: bytes):
        """
        Test message numbers increment correctly
        """
        shared_key = b"0" * 32
        peer_public_key = b"1" * 32

        sender_state = double_ratchet.initialize_sender(
            shared_key = shared_key,
            peer_public_key = peer_public_key
        )

        assert sender_state.sending_message_number == 0

        double_ratchet.encrypt_message(
            sender_state,
            b"Message 1",
            sample_associated_data
        )

        assert sender_state.sending_message_number == 1

        double_ratchet.encrypt_message(
            sender_state,
            b"Message 2",
            sample_associated_data
        )

        assert sender_state.sending_message_number == 2

    def test_tampered_message_fails(self, sample_associated_data: bytes):
        """
        Test tampered messages fail to decrypt
        """
        shared_key = b"0" * 32

        bob_dh_private = X25519PrivateKey.generate()
        bob_dh_public_bytes = bob_dh_private.public_key().public_bytes(
            encoding = serialization.Encoding.Raw,
            format = serialization.PublicFormat.Raw
        )

        sender_state = double_ratchet.initialize_sender(
            shared_key = shared_key,
            peer_public_key = bob_dh_public_bytes
        )

        receiver_state = double_ratchet.initialize_receiver(
            shared_key = shared_key,
            own_private_key = bob_dh_private
        )

        encrypted = double_ratchet.encrypt_message(
            sender_state,
            b"Original message",
            sample_associated_data
        )

        tampered_ciphertext = bytearray(encrypted.ciphertext)
        tampered_ciphertext[0] ^= 0xFF
        encrypted.ciphertext = bytes(tampered_ciphertext)

        with pytest.raises(ValueError, match = "tampered or corrupted"):
            double_ratchet.decrypt_message(
                receiver_state,
                encrypted,
                sample_associated_data
            )
