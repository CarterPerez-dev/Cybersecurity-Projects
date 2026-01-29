"""
ⒸAngelaMos | 2025
Custom application exceptions for clean error handling
"""


class AppException(Exception):
    """
    Base application exception
    """
    def __init__(self, message: str) -> None:
        """
        Initialize exception with message
        """
        self.message = message
        super().__init__(self.message)


class UserExistsError(AppException):
    """
    Raised when attempting to create a user that already exists
    """


class UserNotFoundError(AppException):
    """
    Raised when user cannot be found
    """


class UserInactiveError(AppException):
    """
    Raised when user account is inactive
    """


class CredentialNotFoundError(AppException):
    """
    Raised when credential cannot be found
    """


class CredentialVerificationError(AppException):
    """
    Raised when credential verification fails
    """


class ChallengeExpiredError(AppException):
    """
    Raised when WebAuthn challenge has expired or not found
    """


class DatabaseError(AppException):
    """
    Raised when database operation fails
    """


class AuthenticationError(AppException):
    """
    Raised when authentication fails
    """


class InvalidDataError(AppException):
    """
    Raised when input data is invalid
    """


class EncryptionError(AppException):
    """
    Raised when message encryption fails
    """


class DecryptionError(AppException):
    """
    Raised when message decryption fails
    """


class RatchetStateNotFoundError(AppException):
    """
    Raised when ratchet state not found for conversation
    """


class KeyExchangeError(AppException):
    """
    Raised when X3DH key exchange fails
    """
