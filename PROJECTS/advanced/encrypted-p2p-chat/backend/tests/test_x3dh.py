"""
ⒸAngelaMos | 2025
Tests for X3DH key exchange protocol
"""

from webauthn.helpers import base64url_to_bytes

from app.core.encryption.x3dh_manager import x3dh_manager, PreKeyBundle


class TestX3DH:
    """
    Test X3DH key exchange
    """
    def test_key_generation(self):
        """
        Test all key generation functions work
        """
        ik_private, ik_public = x3dh_manager.generate_identity_keypair_x25519()
        assert len(base64url_to_bytes(ik_private)) == 32
        assert len(base64url_to_bytes(ik_public)) == 32

        ik_private_ed, ik_public_ed = x3dh_manager.generate_identity_keypair_ed25519()
        assert len(base64url_to_bytes(ik_private_ed)) == 32
        assert len(base64url_to_bytes(ik_public_ed)) == 32

        spk_private, spk_public, signature = x3dh_manager.generate_signed_prekey(
            ik_private_ed
        )
        assert len(base64url_to_bytes(spk_private)) == 32
        assert len(base64url_to_bytes(spk_public)) == 32
        assert len(base64url_to_bytes(signature)) == 64

        opk_private, opk_public = x3dh_manager.generate_one_time_prekey()
        assert len(base64url_to_bytes(opk_private)) == 32
        assert len(base64url_to_bytes(opk_public)) == 32

    def test_x3dh_handshake_with_opk(self):
        """
        Test full X3DH handshake with one-time prekey
        """
        alice_ik_private, alice_ik_public = (
            x3dh_manager.generate_identity_keypair_x25519()
        )
        alice_ik_private_ed, alice_ik_public_ed = (
            x3dh_manager.generate_identity_keypair_ed25519()
        )

        bob_ik_private, bob_ik_public = (
            x3dh_manager.generate_identity_keypair_x25519()
        )
        bob_ik_private_ed, bob_ik_public_ed = (
            x3dh_manager.generate_identity_keypair_ed25519()
        )

        bob_spk_private, bob_spk_public, bob_spk_sig = (
            x3dh_manager.generate_signed_prekey(bob_ik_private_ed)
        )

        bob_opk_private, bob_opk_public = x3dh_manager.generate_one_time_prekey()

        bob_bundle = PreKeyBundle(
            identity_key = bob_ik_public,
            signed_prekey = bob_spk_public,
            signed_prekey_signature = bob_spk_sig,
            one_time_prekey = bob_opk_public
        )

        alice_result = x3dh_manager.perform_x3dh_sender(
            alice_identity_private_x25519 = alice_ik_private,
            bob_bundle = bob_bundle,
            bob_identity_public_ed25519 = bob_ik_public_ed
        )

        bob_result = x3dh_manager.perform_x3dh_receiver(
            bob_identity_private_x25519 = bob_ik_private,
            bob_signed_prekey_private = bob_spk_private,
            bob_one_time_prekey_private = bob_opk_private,
            alice_ephemeral_public = alice_result.ephemeral_public_key,
            alice_identity_public_x25519 = alice_ik_public
        )

        assert alice_result.shared_key == bob_result.shared_key
        assert len(alice_result.shared_key) == 32

    def test_x3dh_handshake_without_opk(self):
        """
        Test X3DH handshake without one-time prekey
        """
        alice_ik_private, alice_ik_public = (
            x3dh_manager.generate_identity_keypair_x25519()
        )
        alice_ik_private_ed, alice_ik_public_ed = (
            x3dh_manager.generate_identity_keypair_ed25519()
        )

        bob_ik_private, bob_ik_public = (
            x3dh_manager.generate_identity_keypair_x25519()
        )
        bob_ik_private_ed, bob_ik_public_ed = (
            x3dh_manager.generate_identity_keypair_ed25519()
        )

        bob_spk_private, bob_spk_public, bob_spk_sig = (
            x3dh_manager.generate_signed_prekey(bob_ik_private_ed)
        )

        bob_bundle = PreKeyBundle(
            identity_key = bob_ik_public,
            signed_prekey = bob_spk_public,
            signed_prekey_signature = bob_spk_sig,
            one_time_prekey = None
        )

        alice_result = x3dh_manager.perform_x3dh_sender(
            alice_identity_private_x25519 = alice_ik_private,
            bob_bundle = bob_bundle,
            bob_identity_public_ed25519 = bob_ik_public_ed
        )

        bob_result = x3dh_manager.perform_x3dh_receiver(
            bob_identity_private_x25519 = bob_ik_private,
            bob_signed_prekey_private = bob_spk_private,
            bob_one_time_prekey_private = None,
            alice_ephemeral_public = alice_result.ephemeral_public_key,
            alice_identity_public_x25519 = alice_ik_public
        )

        assert alice_result.shared_key == bob_result.shared_key
        assert len(alice_result.shared_key) == 32
