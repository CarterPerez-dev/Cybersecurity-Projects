"""
©AngelaMos | 2026
auth_service.py
"""

import logging
import secrets
from typing import Any
from uuid import UUID
from datetime import UTC, datetime

from sqlmodel import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import selectinload
from sqlmodel.ext.asyncio.session import AsyncSession
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

from app.config import USER_SEARCH_DEFAULT_LIMIT
from app.core.exceptions import (
    ChallengeExpiredError,
    CredentialNotFoundError,
    CredentialVerificationError,
    DatabaseError,
    InvalidDataError,
    UserExistsError,
    UserInactiveError,
    UserNotFoundError,
)
from app.core.passkey.passkey_manager import passkey_manager
from app.core.redis_manager import redis_manager
from app.models.Credential import Credential
from app.models.User import User
from app.schemas.auth import (
    AuthenticationBeginRequest,
    AuthenticationCompleteRequest,
    RegistrationBeginRequest,
    RegistrationCompleteRequest,
    VerifiedRegistration,
)


logger = logging.getLogger(__name__)


class AuthService:
    """
    Service for managing user authentication and credentials
    """
    async def create_user(
        self,
        session: AsyncSession,
        username: str,
        display_name: str,
        webauthn_user_handle: bytes,
    ) -> User:
        """
        Create a new user with username uniqueness check
        """
        statement = select(User).where(User.username == username)
        result = await session.execute(statement)
        existing_user = result.scalar_one_or_none()

        if existing_user:
            logger.warning("Attempted to create duplicate user: %s", username)
            raise UserExistsError(f"Username {username} already exists")

        user = User(
            username = username,
            display_name = display_name,
            webauthn_user_handle = webauthn_user_handle,
        )

        session.add(user)

        try:
            await session.commit()
            await session.refresh(user)
            logger.info("Created new user: %s (ID: %s)", username, user.id)
            return user
        except IntegrityError as e:
            await session.rollback()
            logger.error("Database integrity error creating user %s: %s", username, e)
            raise DatabaseError(
                "Failed to create user: database constraint violation"
            ) from e

    async def store_credential(
        self,
        session: AsyncSession,
        user_id: UUID,
        verified: VerifiedRegistration,
        device_name: str | None = None,
    ) -> Credential:
        """
        Store WebAuthn credential after successful registration
        """
        credential = Credential(
            user_id = user_id,
            credential_id = bytes_to_base64url(verified.credential_id),
            public_key = bytes_to_base64url(verified.credential_public_key),
            sign_count = verified.sign_count,
            aaguid = bytes_to_base64url(verified.aaguid),
            backup_eligible = verified.backup_eligible,
            backup_state = verified.backup_state,
            attestation_type = verified.attestation_format,
            device_name = device_name,
            last_used_at = datetime.now(UTC),
        )

        session.add(credential)

        try:
            await session.commit()
            await session.refresh(credential)
            logger.info(
                "Stored credential %s... for user %s",
                credential.credential_id[: 16],
                user_id
            )
            return credential
        except IntegrityError as e:
            await session.rollback()
            logger.error("Database integrity error storing credential: %s", e)
            raise DatabaseError(
                "Failed to store credential: database constraint violation"
            ) from e

    async def get_user_by_username(
        self,
        session: AsyncSession,
        username: str,
    ) -> User | None:
        """
        Retrieve user by username with credentials relationship eager loaded
        """
        statement = (
            select(User).where(User.username == username).options(
                selectinload(User.credentials)
            )
        )
        result = await session.execute(statement)
        user = result.scalar_one_or_none()

        if user:
            logger.debug(
                "Retrieved user %s with %s credentials",
                username,
                len(user.credentials)
            )
        else:
            logger.debug("User not found: %s", username)

        return user

    async def get_user_by_id(
        self,
        session: AsyncSession,
        user_id: UUID,
    ) -> User | None:
        """
        Retrieve user by ID with credentials relationship eager loaded
        """
        statement = (
            select(User).where(User.id == user_id).options(
                selectinload(User.credentials)
            )
        )
        result = await session.execute(statement)
        user = result.scalar_one_or_none()

        if user:
            logger.debug(
                "Retrieved user %s with %s credentials",
                user_id,
                len(user.credentials)
            )
        else:
            logger.debug("User not found: %s", user_id)

        return user

    async def search_users(
        self,
        session: AsyncSession,
        query: str,
        limit: int = USER_SEARCH_DEFAULT_LIMIT,
        exclude_user_id: UUID | None = None,
    ) -> list[User]:
        """
        Search for active users by username or display name
        """
        search_pattern = f"%{query.lower()}%"

        statement = (
            select(User).where(
                User.is_active == True,
                (
                    User.username.ilike(search_pattern)
                    | User.display_name.ilike(search_pattern)
                )
            ).limit(limit)
        )

        if exclude_user_id is not None:
            statement = statement.where(User.id != exclude_user_id)

        result = await session.execute(statement)
        users = result.scalars().all()

        logger.debug("Search for '%s' returned %d users", query, len(users))

        return list(users)

    async def get_credential_by_id(
        self,
        session: AsyncSession,
        credential_id: str,
    ) -> Credential | None:
        """
        Retrieve credential by credential_id
        """
        statement = select(Credential).where(Credential.credential_id == credential_id)
        result = await session.execute(statement)
        credential = result.scalar_one_or_none()

        if credential:
            logger.debug("Retrieved credential %s...", credential_id[: 16])
        else:
            logger.debug("Credential not found: %s...", credential_id[: 16])

        return credential

    async def update_credential_counter(
        self,
        session: AsyncSession,
        credential_id: str,
        new_count: int,
    ) -> None:
        """
        Update credential signature counter after successful authentication
        """
        statement = select(Credential).where(Credential.credential_id == credential_id)
        result = await session.execute(statement)
        credential = result.scalar_one_or_none()

        if not credential:
            logger.error(
                "Credential not found for counter update: %s...",
                credential_id[: 16]
            )
            raise CredentialNotFoundError("Credential not found")

        old_count = credential.sign_count
        credential.sign_count = new_count
        credential.last_used_at = datetime.now(UTC)

        try:
            await session.commit()
            logger.info(
                "Updated credential %s... counter: %s -> %s",
                credential_id[: 16],
                old_count,
                new_count
            )
        except IntegrityError as e:
            await session.rollback()
            logger.error("Database error updating credential counter: %s", e)
            raise DatabaseError("Failed to update credential counter") from e

    async def update_backup_state(
        self,
        session: AsyncSession,
        credential_id: str,
        backup_state: bool,
        backup_eligible: bool,
    ) -> None:
        """
        Update credential backup flags (WebAuthn Level 3)
        """
        statement = select(Credential).where(Credential.credential_id == credential_id)
        result = await session.execute(statement)
        credential = result.scalar_one_or_none()

        if not credential:
            logger.error(
                "Credential not found for backup state update: %s...",
                credential_id[: 16]
            )
            raise CredentialNotFoundError("Credential not found")

        if credential.backup_state != backup_state:
            logger.warning(
                "Credential %s... backup state changed: %s -> %s",
                credential_id[: 16],
                credential.backup_state,
                backup_state
            )

        credential.backup_state = backup_state
        credential.backup_eligible = backup_eligible

        try:
            await session.commit()
            logger.debug(
                "Updated credential %s... backup_state=%s, backup_eligible=%s",
                credential_id[: 16],
                backup_state,
                backup_eligible
            )
        except IntegrityError as e:
            await session.rollback()
            logger.error("Database error updating backup state: %s", e)
            raise DatabaseError("Failed to update backup state") from e

    async def begin_registration(
        self,
        session: AsyncSession,
        request: RegistrationBeginRequest,
    ) -> dict[str,
              Any]:
        """
        Begin WebAuthn passkey registration flow
        """
        existing_user = await self.get_user_by_username(
            session = session,
            username = request.username,
        )

        if existing_user:
            logger.warning(
                "Registration attempt for existing user: %s",
                request.username
            )
            raise UserExistsError(f"Username {request.username} already exists")

        from app.config import WEBAUTHN_USER_HANDLE_BYTES
        user_handle = secrets.token_bytes(WEBAUTHN_USER_HANDLE_BYTES)

        options_response = passkey_manager.generate_registration_options(
            user_id = user_handle,
            username = request.username,
            display_name = request.display_name,
            exclude_credentials = [],
        )

        await redis_manager.set_registration_context(
            username = request.username,
            challenge = options_response.challenge,
            user_handle = user_handle,
            display_name = request.display_name,
        )

        logger.info("Started registration for user: %s", request.username)
        return options_response.options

    async def complete_registration(
        self,
        session: AsyncSession,
        request: RegistrationCompleteRequest,
        username: str,
    ) -> User:
        """
        Complete WebAuthn passkey registration
        """
        context = await redis_manager.take_registration_context(username = username)

        if context is None:
            logger.warning(
                "Registration context not found or expired for user: %s",
                username
            )
            raise ChallengeExpiredError(
                "Challenge expired or not found - please restart registration"
            )

        try:
            verified = passkey_manager.verify_registration(
                credential = request.credential,
                expected_challenge = context["challenge"],
            )
        except Exception as e:
            logger.error("Registration verification failed: %s", e)
            raise CredentialVerificationError(
                f"Registration verification failed: {str(e)}"
            ) from e

        user = await self.create_user(
            session = session,
            username = username,
            display_name = context["display_name"],
            webauthn_user_handle = context["user_handle"],
        )

        await self.store_credential(
            session = session,
            user_id = user.id,
            verified = verified,
            device_name = request.device_name,
        )

        logger.info("Registration completed for user: %s", username)
        return user

    async def begin_authentication(
        self,
        session: AsyncSession,
        request: AuthenticationBeginRequest,
    ) -> dict[str,
              Any]:
        """
        Begin WebAuthn passkey authentication flow
        """
        allow_credentials = None

        if request.username:
            user = await self.get_user_by_username(
                session = session,
                username = request.username,
            )

            if user is not None and user.is_active:
                allow_credentials = [
                    base64url_to_bytes(cred.credential_id) for cred in user.credentials
                ]

        options_response = passkey_manager.generate_authentication_options(
            allow_credentials = allow_credentials,
        )

        await redis_manager.set_authentication_challenge(
            challenge = options_response.challenge,
        )

        logger.info(
            "Started authentication (username hint: %s)",
            request.username or "<discoverable>"
        )
        return options_response.options

    async def complete_authentication(
        self,
        session: AsyncSession,
        request: AuthenticationCompleteRequest,
    ) -> User:
        """
        Complete WebAuthn passkey authentication
        """
        credential_id = request.credential.get("id")
        if not credential_id:
            raise InvalidDataError("Missing credential ID")

        client_data_b64 = request.credential.get("response", {}).get("clientDataJSON")
        if not client_data_b64:
            raise InvalidDataError("Missing clientDataJSON")

        try:
            import json as _json
            client_data = _json.loads(base64url_to_bytes(client_data_b64).decode())
            challenge_bytes = base64url_to_bytes(client_data["challenge"])
        except Exception as exc:
            logger.error("Failed to parse clientDataJSON: %s", exc)
            raise InvalidDataError("Malformed clientDataJSON") from exc

        challenge_consumed = await redis_manager.take_authentication_challenge(
            challenge = challenge_bytes
        )
        if not challenge_consumed:
            logger.warning("Authentication challenge invalid or expired")
            raise ChallengeExpiredError(
                "Challenge expired or not found - please restart authentication"
            )

        credential = await self.get_credential_by_id(
            session = session,
            credential_id = credential_id,
        )

        if not credential:
            logger.warning(
                "Authentication with unknown credential: %s...",
                credential_id[: 16]
            )
            raise CredentialNotFoundError("Credential not found")

        user = await self.get_user_by_id(
            session = session,
            user_id = credential.user_id,
        )

        if not user:
            logger.error("User not found for credential: %s...", credential_id[: 16])
            raise UserNotFoundError("User not found")

        if not user.is_active:
            logger.warning(
                "Authentication attempt for inactive user: %s",
                user.username
            )
            raise UserInactiveError("User account is inactive")

        try:
            verified = passkey_manager.verify_authentication(
                credential = request.credential,
                expected_challenge = challenge_bytes,
                credential_public_key = base64url_to_bytes(credential.public_key),
                credential_current_sign_count = credential.sign_count,
            )
        except ValueError as e:
            logger.error("Authentication verification failed: %s", e)
            raise CredentialVerificationError(str(e)) from e
        except Exception as e:
            logger.error("Unexpected error during authentication: %s", e)
            raise CredentialVerificationError(
                "Authentication verification failed"
            ) from e

        await self.update_credential_counter(
            session = session,
            credential_id = credential.credential_id,
            new_count = verified.new_sign_count,
        )

        if (credential.backup_state != verified.backup_state
                or credential.backup_eligible != verified.backup_eligible):
            await self.update_backup_state(
                session = session,
                credential_id = credential.credential_id,
                backup_state = verified.backup_state,
                backup_eligible = verified.backup_eligible,
            )

        logger.info("Authentication successful for user: %s", user.username)
        return user


auth_service = AuthService()
