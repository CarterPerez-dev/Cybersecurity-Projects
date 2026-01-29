"""
ⒸAngelaMos | 2025
X3DH key exchange manager for async initial key agreement
"""

import logging
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.exceptions import InvalidSignature
from webauthn.helpers import (
    bytes_to_base64url,
    base64url_to_bytes,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.config import (
    X25519_KEY_SIZE,
)


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


@dataclass
class X3DHResult:
    """
    Result of X3DH key exchange containing shared key and metadata
    """
    shared_key: bytes
    associated_data: bytes
    ephemeral_public_key: str
    used_one_time_prekey: bool


class X3DHManager:
    """
    Manages X3DH key exchange protocol for async initial key agreement
    """
    def generate_identity_keypair_x25519(self) -> tuple[str, str]:
        """
        Generates X25519 identity keypair for DH operations
        """
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()

        private_bytes = private_key.private_bytes(
            encoding = serialization.Encoding.Raw,
            format = serialization.PrivateFormat.Raw,
            encryption_algorithm = serialization.NoEncryption()
        )
        public_bytes = public_key.public_bytes(
            encoding = serialization.Encoding.Raw,
            format = serialization.PublicFormat.Raw
        )

        logger.debug(
            "Generated X25519 identity keypair: %s private, %s public bytes",
            len(private_bytes),
            len(public_bytes)
        )

        return (
            bytes_to_base64url(private_bytes),
            bytes_to_base64url(public_bytes)
        )

    def generate_identity_keypair_ed25519(self) -> tuple[str, str]:
        """
        Generates Ed25519 identity keypair for signing prekeys
        """
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        private_bytes = private_key.private_bytes(
            encoding = serialization.Encoding.Raw,
            format = serialization.PrivateFormat.Raw,
            encryption_algorithm = serialization.NoEncryption()
        )
        public_bytes = public_key.public_bytes(
            encoding = serialization.Encoding.Raw,
            format = serialization.PublicFormat.Raw
        )

        logger.debug(
            "Generated Ed25519 signing keypair: %s private, %s public bytes",
            len(private_bytes),
            len(public_bytes)
        )

        return (
            bytes_to_base64url(private_bytes),
            bytes_to_base64url(public_bytes)
        )

    def generate_signed_prekey(self,
                               identity_private_key_ed25519: str) -> tuple[str,
                                                                           str,
                                                                           str]:
        """
        Generates signed prekey with signature from Ed25519 identity key
        """
        spk_private = X25519PrivateKey.generate()
        spk_public = spk_private.public_key()

        spk_private_bytes = spk_private.private_bytes(
            encoding = serialization.Encoding.Raw,
            format = serialization.PrivateFormat.Raw,
            encryption_algorithm = serialization.NoEncryption()
        )
        spk_public_bytes = spk_public.public_bytes(
            encoding = serialization.Encoding.Raw,
            format = serialization.PublicFormat.Raw
        )

        identity_private_bytes = base64url_to_bytes(identity_private_key_ed25519)
        identity_private = Ed25519PrivateKey.from_private_bytes(
            identity_private_bytes
        )

        signature = identity_private.sign(spk_public_bytes)

        logger.debug(
            "Generated signed prekey with %s byte signature",
            len(signature)
        )

        return (
            bytes_to_base64url(spk_private_bytes),
            bytes_to_base64url(spk_public_bytes),
            bytes_to_base64url(signature)
        )

    def generate_one_time_prekey(self) -> tuple[str, str]:
        """
        Generates single-use one-time prekey
        """
        opk_private = X25519PrivateKey.generate()
        opk_public = opk_private.public_key()

        opk_private_bytes = opk_private.private_bytes(
            encoding = serialization.Encoding.Raw,
            format = serialization.PrivateFormat.Raw,
            encryption_algorithm = serialization.NoEncryption()
        )
        opk_public_bytes = opk_public.public_bytes(
            encoding = serialization.Encoding.Raw,
            format = serialization.PublicFormat.Raw
        )

        return (
            bytes_to_base64url(opk_private_bytes),
            bytes_to_base64url(opk_public_bytes)
        )

    def verify_signed_prekey(
        self,
        signed_prekey_public: str,
        signature: str,
        identity_public_key_ed25519: str
    ) -> bool:
        """
        Verifies signed prekey signature using Ed25519 identity key
        """
        try:
            spk_public_bytes = base64url_to_bytes(signed_prekey_public)
            signature_bytes = base64url_to_bytes(signature)
            identity_public_bytes = base64url_to_bytes(
                identity_public_key_ed25519
            )

            identity_public = Ed25519PublicKey.from_public_bytes(
                identity_public_bytes
            )

            identity_public.verify(signature_bytes, spk_public_bytes)

            logger.debug("Signed prekey signature verified successfully")
            return True

        except InvalidSignature:
            logger.warning("Signed prekey signature verification failed")
            return False
        except Exception as e:
            logger.error("Error verifying signed prekey: %s", e)
            return False

    def perform_x3dh_sender(
        self,
        alice_identity_private_x25519: str,
        bob_bundle: PreKeyBundle,
        bob_identity_public_ed25519: str
    ) -> X3DHResult:
        """
        Performs X3DH key exchange from sender side
        """
        if not self.verify_signed_prekey(bob_bundle.signed_prekey,
                                         bob_bundle.signed_prekey_signature,
                                         bob_identity_public_ed25519):
            raise ValueError("Invalid signed prekey signature")

        alice_ik_private_bytes = base64url_to_bytes(alice_identity_private_x25519)
        alice_ik_private = X25519PrivateKey.from_private_bytes(
            alice_ik_private_bytes
        )

        alice_ek_private = X25519PrivateKey.generate()
        alice_ek_public = alice_ek_private.public_key()

        alice_ek_public_bytes = alice_ek_public.public_bytes(
            encoding = serialization.Encoding.Raw,
            format = serialization.PublicFormat.Raw
        )

        bob_ik_public_bytes = base64url_to_bytes(bob_bundle.identity_key)
        bob_ik_public = X25519PublicKey.from_public_bytes(bob_ik_public_bytes)

        bob_spk_public_bytes = base64url_to_bytes(bob_bundle.signed_prekey)
        bob_spk_public = X25519PublicKey.from_public_bytes(bob_spk_public_bytes)

        dh1 = alice_ik_private.exchange(bob_spk_public)
        dh2 = alice_ek_private.exchange(bob_ik_public)
        dh3 = alice_ek_private.exchange(bob_spk_public)

        used_one_time_prekey = False
        if bob_bundle.one_time_prekey:
            bob_opk_public_bytes = base64url_to_bytes(bob_bundle.one_time_prekey)
            bob_opk_public = X25519PublicKey.from_public_bytes(
                bob_opk_public_bytes
            )
            dh4 = alice_ek_private.exchange(bob_opk_public)
            key_material = dh1 + dh2 + dh3 + dh4
            used_one_time_prekey = True
        else:
            key_material = dh1 + dh2 + dh3

        f = b'\xff' * X25519_KEY_SIZE
        hkdf = HKDF(
            algorithm = hashes.SHA256(),
            length = X25519_KEY_SIZE,
            salt = b'\x00' * X25519_KEY_SIZE,
            info = b'X3DH',
        )
        shared_key = hkdf.derive(f + key_material)

        alice_ik_public = alice_ik_private.public_key()
        alice_ik_public_bytes = alice_ik_public.public_bytes(
            encoding = serialization.Encoding.Raw,
            format = serialization.PublicFormat.Raw
        )

        associated_data = alice_ik_public_bytes + bob_ik_public_bytes

        logger.info("X3DH sender completed: OPK used=%s", used_one_time_prekey)

        return X3DHResult(
            shared_key = shared_key,
            associated_data = associated_data,
            ephemeral_public_key = bytes_to_base64url(alice_ek_public_bytes),
            used_one_time_prekey = used_one_time_prekey
        )

    def perform_x3dh_receiver(
        self,
        bob_identity_private_x25519: str,
        bob_signed_prekey_private: str,
        bob_one_time_prekey_private: str | None,
        alice_identity_public_x25519: str,
        alice_ephemeral_public: str
    ) -> X3DHResult:
        """
        Performs X3DH key exchange from receiver side
        """
        bob_ik_private_bytes = base64url_to_bytes(bob_identity_private_x25519)
        bob_ik_private = X25519PrivateKey.from_private_bytes(bob_ik_private_bytes)

        bob_spk_private_bytes = base64url_to_bytes(bob_signed_prekey_private)
        bob_spk_private = X25519PrivateKey.from_private_bytes(
            bob_spk_private_bytes
        )

        alice_ik_public_bytes = base64url_to_bytes(alice_identity_public_x25519)
        alice_ik_public = X25519PublicKey.from_public_bytes(alice_ik_public_bytes)

        alice_ek_public_bytes = base64url_to_bytes(alice_ephemeral_public)
        alice_ek_public = X25519PublicKey.from_public_bytes(alice_ek_public_bytes)

        dh1 = bob_spk_private.exchange(alice_ik_public)
        dh2 = bob_ik_private.exchange(alice_ek_public)
        dh3 = bob_spk_private.exchange(alice_ek_public)

        used_one_time_prekey = False
        if bob_one_time_prekey_private:
            bob_opk_private_bytes = base64url_to_bytes(
                bob_one_time_prekey_private
            )
            bob_opk_private = X25519PrivateKey.from_private_bytes(
                bob_opk_private_bytes
            )
            dh4 = bob_opk_private.exchange(alice_ek_public)
            key_material = dh1 + dh2 + dh3 + dh4
            used_one_time_prekey = True
        else:
            key_material = dh1 + dh2 + dh3

        f = b'\xff' * X25519_KEY_SIZE
        hkdf = HKDF(
            algorithm = hashes.SHA256(),
            length = X25519_KEY_SIZE,
            salt = b'\x00' * X25519_KEY_SIZE,
            info = b'X3DH',
        )
        shared_key = hkdf.derive(f + key_material)

        bob_ik_public = bob_ik_private.public_key()
        bob_ik_public_bytes = bob_ik_public.public_bytes(
            encoding = serialization.Encoding.Raw,
            format = serialization.PublicFormat.Raw
        )

        associated_data = alice_ik_public_bytes + bob_ik_public_bytes

        logger.info("X3DH receiver completed: OPK used=%s", used_one_time_prekey)

        return X3DHResult(
            shared_key = shared_key,
            associated_data = associated_data,
            ephemeral_public_key = alice_ephemeral_public,
            used_one_time_prekey = used_one_time_prekey
        )


x3dh_manager = X3DHManager()
