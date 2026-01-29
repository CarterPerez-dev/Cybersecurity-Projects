"""
ⒸAngelaMos | 2025
WebAuthn passkey manager using py_webauthn library
"""

import logging
import secrets
from typing import Any

from webauthn.helpers import (
    bytes_to_base64url,
    options_to_json_dict,
)
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from app.config import (
    settings,
    WEBAUTHN_CHALLENGE_BYTES,
)
from app.schemas.auth import (
    AuthenticationOptionsResponse,
    RegistrationOptionsResponse,
    VerifiedAuthentication,
    VerifiedRegistration,
)


logger = logging.getLogger(__name__)


class PasskeyManager:
    """
    WebAuthn passkey manager for registration and authentication
    """
    def __init__(self) -> None:
        """
        Initialize passkey manager with RP configuration
        """
        self.rp_id = settings.RP_ID
        self.rp_name = settings.RP_NAME
        self.rp_origin = settings.RP_ORIGIN

    def generate_registration_options(
        self,
        user_id: bytes,
        username: str,
        display_name: str,
        exclude_credentials: list[bytes] | None = None,
    ) -> RegistrationOptionsResponse:
        """
        Generate WebAuthn registration options for passkey creation
        """
        challenge = secrets.token_bytes(WEBAUTHN_CHALLENGE_BYTES)

        exclude_creds = []
        if exclude_credentials:
            exclude_creds = [
                PublicKeyCredentialDescriptor(id = cred_id)
                for cred_id in exclude_credentials
            ]

        options = generate_registration_options(
            rp_id = self.rp_id,
            rp_name = self.rp_name,
            user_id = user_id,
            user_name = username,
            user_display_name = display_name,
            challenge = challenge,
            attestation = AttestationConveyancePreference.NONE,
            authenticator_selection = AuthenticatorSelectionCriteria(
                resident_key = ResidentKeyRequirement.REQUIRED,
                user_verification = UserVerificationRequirement.PREFERRED,
            ),
            exclude_credentials = exclude_creds,
        )

        logger.debug("Generated registration options for user %s", username)

        return RegistrationOptionsResponse(
            options = options_to_json_dict(options),
            challenge = challenge,
        )

    def verify_registration(
        self,
        credential: dict[str,
                         Any],
        expected_challenge: bytes,
    ) -> VerifiedRegistration:
        """
        Verify WebAuthn registration response
        """
        verified_registration = verify_registration_response(
            credential = credential,
            expected_challenge = expected_challenge,
            expected_rp_id = self.rp_id,
            expected_origin = self.rp_origin,
        )

        logger.info(
            "Verified registration for credential %s...",
            bytes_to_base64url(verified_registration.credential_id)[: 16]
        )

        return VerifiedRegistration(
            credential_id = verified_registration.credential_id,
            credential_public_key = verified_registration.credential_public_key,
            sign_count = verified_registration.sign_count,
            aaguid = verified_registration.aaguid,
            attestation_object = verified_registration.attestation_object,
            credential_type = verified_registration.credential_type,
            user_verified = verified_registration.user_verified,
            attestation_format = verified_registration.fmt,
            credential_device_type = verified_registration.credential_device_type,
            credential_backed_up = verified_registration.credential_backed_up,
            backup_eligible = verified_registration.credential_backed_up,
            backup_state = verified_registration.credential_backed_up,
        )

    def generate_authentication_options(
        self,
        allow_credentials: list[bytes] | None = None,
    ) -> AuthenticationOptionsResponse:
        """
        Generate WebAuthn authentication options for passkey verification
        """
        challenge = secrets.token_bytes(WEBAUTHN_CHALLENGE_BYTES)

        allow_creds = None
        if allow_credentials:
            allow_creds = [
                PublicKeyCredentialDescriptor(id = cred_id)
                for cred_id in allow_credentials
            ]

        options = generate_authentication_options(
            rp_id = self.rp_id,
            challenge = challenge,
            allow_credentials = allow_creds,
            user_verification = UserVerificationRequirement.PREFERRED,
        )

        logger.debug("Generated authentication options")

        return AuthenticationOptionsResponse(
            options = options_to_json_dict(options),
            challenge = challenge,
        )

    def verify_authentication(
        self,
        credential: dict[str,
                         Any],
        expected_challenge: bytes,
        credential_public_key: bytes,
        credential_current_sign_count: int,
    ) -> VerifiedAuthentication:
        """
        Verify WebAuthn authentication response and check signature counter
        """
        verified_authentication = verify_authentication_response(
            credential = credential,
            expected_challenge = expected_challenge,
            expected_rp_id = self.rp_id,
            expected_origin = self.rp_origin,
            credential_public_key = credential_public_key,
            credential_current_sign_count = credential_current_sign_count,
        )

        new_sign_count = verified_authentication.new_sign_count

        if (credential_current_sign_count != 0 and new_sign_count != 0
                and new_sign_count <= credential_current_sign_count):
            logger.error(
                "Signature counter did not increase: current=%s, new=%s. Possible cloned authenticator detected!",
                credential_current_sign_count,
                new_sign_count
            )
            raise ValueError(
                "Signature counter anomaly detected - potential cloned authenticator"
            )

        logger.info(
            "Verified authentication with counter %s -> %s",
            credential_current_sign_count,
            new_sign_count
        )

        return VerifiedAuthentication(
            new_sign_count = new_sign_count,
            credential_id = verified_authentication.credential_id,
            user_verified = verified_authentication.user_verified,
            backup_state = verified_authentication.credential_backed_up,
            backup_eligible = verified_authentication.credential_backup_eligible,
        )


passkey_manager = PasskeyManager()
