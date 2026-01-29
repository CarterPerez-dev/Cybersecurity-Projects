"""
ⒸAngelaMos | 2025
Global exception handlers for FastAPI application
"""

import logging

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from app.core.exceptions import (
    AuthenticationError,
    ChallengeExpiredError,
    CredentialNotFoundError,
    CredentialVerificationError,
    DatabaseError,
    DecryptionError,
    EncryptionError,
    InvalidDataError,
    KeyExchangeError,
    RatchetStateNotFoundError,
    UserExistsError,
    UserInactiveError,
    UserNotFoundError,
)


logger = logging.getLogger(__name__)


async def user_exists_handler(
    request: Request,
    exc: UserExistsError
) -> JSONResponse:
    """
    Handle UserExistsError exceptions
    """
    logger.warning("User exists error on %s: %s", request.url, exc.message)
    return JSONResponse(
        status_code = status.HTTP_409_CONFLICT,
        content = {"detail": exc.message},
    )


async def user_not_found_handler(
    request: Request,
    exc: UserNotFoundError
) -> JSONResponse:
    """
    Handle UserNotFoundError exceptions
    """
    logger.warning("User not found on %s: %s", request.url, exc.message)
    return JSONResponse(
        status_code = status.HTTP_404_NOT_FOUND,
        content = {"detail": exc.message},
    )


async def user_inactive_handler(
    request: Request,
    exc: UserInactiveError
) -> JSONResponse:
    """
    Handle UserInactiveError exceptions
    """
    logger.warning(
        "Inactive user access attempt on %s: %s",
        request.url,
        exc.message
    )
    return JSONResponse(
        status_code = status.HTTP_403_FORBIDDEN,
        content = {"detail": exc.message},
    )


async def credential_not_found_handler(
    request: Request,
    exc: CredentialNotFoundError
) -> JSONResponse:
    """
    Handle CredentialNotFoundError exceptions
    """
    logger.warning("Credential not found on %s: %s", request.url, exc.message)
    return JSONResponse(
        status_code = status.HTTP_404_NOT_FOUND,
        content = {"detail": exc.message},
    )


async def credential_verification_handler(
    request: Request,
    exc: CredentialVerificationError
) -> JSONResponse:
    """
    Handle CredentialVerificationError exceptions
    """
    logger.error(
        "Credential verification failed on %s: %s",
        request.url,
        exc.message
    )
    return JSONResponse(
        status_code = status.HTTP_401_UNAUTHORIZED,
        content = {"detail": exc.message},
    )


async def challenge_expired_handler(
    request: Request,
    exc: ChallengeExpiredError
) -> JSONResponse:
    """
    Handle ChallengeExpiredError exceptions
    """
    logger.warning("Challenge expired on %s: %s", request.url, exc.message)
    return JSONResponse(
        status_code = status.HTTP_400_BAD_REQUEST,
        content = {"detail": exc.message},
    )


async def database_error_handler(
    request: Request,
    exc: DatabaseError
) -> JSONResponse:
    """
    Handle DatabaseError exceptions
    """
    logger.error("Database error on %s: %s", request.url, exc.message)
    return JSONResponse(
        status_code = status.HTTP_500_INTERNAL_SERVER_ERROR,
        content = {"detail": "Internal server error"},
    )


async def authentication_error_handler(
    request: Request,
    exc: AuthenticationError
) -> JSONResponse:
    """
    Handle AuthenticationError exceptions
    """
    logger.warning("Authentication error on %s: %s", request.url, exc.message)
    return JSONResponse(
        status_code = status.HTTP_401_UNAUTHORIZED,
        content = {"detail": exc.message},
    )


async def invalid_data_handler(
    request: Request,
    exc: InvalidDataError
) -> JSONResponse:
    """
    Handle InvalidDataError exceptions
    """
    logger.warning("Invalid data on %s: %s", request.url, exc.message)
    return JSONResponse(
        status_code = status.HTTP_400_BAD_REQUEST,
        content = {"detail": exc.message},
    )


async def encryption_error_handler(
    request: Request,
    exc: EncryptionError
) -> JSONResponse:
    """
    Handle EncryptionError exceptions
    """
    logger.error("Encryption error on %s: %s", request.url, exc.message)
    return JSONResponse(
        status_code = status.HTTP_500_INTERNAL_SERVER_ERROR,
        content = {"detail": "Encryption failed"},
    )


async def decryption_error_handler(
    request: Request,
    exc: DecryptionError
) -> JSONResponse:
    """
    Handle DecryptionError exceptions
    """
    logger.error("Decryption error on %s: %s", request.url, exc.message)
    return JSONResponse(
        status_code = status.HTTP_500_INTERNAL_SERVER_ERROR,
        content = {"detail": "Decryption failed"},
    )


async def ratchet_state_not_found_handler(
    request: Request,
    exc: RatchetStateNotFoundError
) -> JSONResponse:
    """
    Handle RatchetStateNotFoundError exceptions
    """
    logger.warning("Ratchet state not found on %s: %s", request.url, exc.message)
    return JSONResponse(
        status_code = status.HTTP_404_NOT_FOUND,
        content = {"detail": exc.message},
    )


async def key_exchange_error_handler(
    request: Request,
    exc: KeyExchangeError
) -> JSONResponse:
    """
    Handle KeyExchangeError exceptions
    """
    logger.error("Key exchange error on %s: %s", request.url, exc.message)
    return JSONResponse(
        status_code = status.HTTP_500_INTERNAL_SERVER_ERROR,
        content = {"detail": "Key exchange failed"},
    )


def register_exception_handlers(app: FastAPI) -> None:
    """
    Register all custom exception handlers with FastAPI app
    """
    app.add_exception_handler(UserExistsError, user_exists_handler)
    app.add_exception_handler(UserNotFoundError, user_not_found_handler)
    app.add_exception_handler(UserInactiveError, user_inactive_handler)
    app.add_exception_handler(
        CredentialNotFoundError,
        credential_not_found_handler
    )
    app.add_exception_handler(
        CredentialVerificationError,
        credential_verification_handler
    )
    app.add_exception_handler(ChallengeExpiredError, challenge_expired_handler)
    app.add_exception_handler(DatabaseError, database_error_handler)
    app.add_exception_handler(AuthenticationError, authentication_error_handler)
    app.add_exception_handler(InvalidDataError, invalid_data_handler)
    app.add_exception_handler(EncryptionError, encryption_error_handler)
    app.add_exception_handler(DecryptionError, decryption_error_handler)
    app.add_exception_handler(
        RatchetStateNotFoundError,
        ratchet_state_not_found_handler
    )
    app.add_exception_handler(KeyExchangeError, key_exchange_error_handler)
