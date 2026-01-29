"""
ⒸAngelaMos | 2025
exceptions.py
"""

from typing import Any


class BaseAppException(Exception):
    """
    Base exception for all application specific errors
    """
    def __init__(
        self,
        message: str,
        status_code: int = 500,
        extra: dict[str,
                    Any] | None = None,
    ) -> None:
        self.message = message
        self.status_code = status_code
        self.extra = extra or {}
        super().__init__(self.message)


class ResourceNotFound(BaseAppException):
    """
    Raised when a requested resource does not exist
    """
    def __init__(
        self,
        resource: str,
        identifier: str | int,
        extra: dict[str,
                    Any] | None = None,
    ) -> None:
        super().__init__(
            message = f"{resource} with id '{identifier}' not found",
            status_code = 404,
            extra = extra,
        )
        self.resource = resource
        self.identifier = identifier


class ConflictError(BaseAppException):
    """
    Raised when an operation conflicts with existing state
    """
    def __init__(
        self,
        message: str,
        extra: dict[str,
                    Any] | None = None,
    ) -> None:
        super().__init__(
            message = message,
            status_code = 409,
            extra = extra
        )


class ValidationError(BaseAppException):
    """
    Raised when input validation fails outside of Pydantic
    """
    def __init__(
        self,
        message: str,
        field: str | None = None,
        extra: dict[str,
                    Any] | None = None,
    ) -> None:
        super().__init__(
            message = message,
            status_code = 422,
            extra = extra
        )
        self.field = field


class AuthenticationError(BaseAppException):
    """
    Raised when authentication fails
    """
    def __init__(
        self,
        message: str = "Authentication failed",
        extra: dict[str,
                    Any] | None = None,
    ) -> None:
        super().__init__(
            message = message,
            status_code = 401,
            extra = extra
        )


class TokenError(AuthenticationError):
    """
    Raised for JWT token specific errors
    """
    def __init__(
        self,
        message: str = "Invalid or expired token",
        extra: dict[str,
                    Any] | None = None,
    ) -> None:
        super().__init__(message = message, extra = extra)


class TokenRevokedError(TokenError):
    """
    Raised when a revoked token is used
    """
    def __init__(self, extra: dict[str, Any] | None = None) -> None:
        super().__init__(message = "Token has been revoked", extra = extra)


class PermissionDenied(BaseAppException):
    """
    Raised when user lacks required permissions
    """
    def __init__(
        self,
        message: str = "Permission denied",
        required_permission: str | None = None,
        extra: dict[str,
                    Any] | None = None,
    ) -> None:
        super().__init__(
            message = message,
            status_code = 403,
            extra = extra
        )
        self.required_permission = required_permission


class RateLimitExceeded(BaseAppException):
    """
    Raised when rate limit is exceeded
    """
    def __init__(
        self,
        message: str = "Calm down a little bit...",
        retry_after: int | None = None,
        extra: dict[str,
                    Any] | None = None,
    ) -> None:
        super().__init__(
            message = message,
            status_code = 420,
            extra = extra
        )
        self.retry_after = retry_after


class UserNotFound(ResourceNotFound):
    """
    Raised when a user is not found
    """
    def __init__(
        self,
        identifier: str | int,
        extra: dict[str,
                    Any] | None = None,
    ) -> None:
        super().__init__(
            resource = "User",
            identifier = identifier,
            extra = extra
        )


class EmailAlreadyExists(ConflictError):
    """
    Raised when attempting to register with an existing email
    """
    def __init__(
        self,
        email: str,
        extra: dict[str,
                    Any] | None = None
    ) -> None:
        super().__init__(
            message = f"Email '{email}' is already registered",
            extra = extra,
        )
        self.email = email


class InvalidCredentials(AuthenticationError):
    """
    Raised when login credentials are invalid
    """
    def __init__(self, extra: dict[str, Any] | None = None) -> None:
        super().__init__(
            message = "Invalid email or password",
            extra = extra
        )


class InactiveUser(AuthenticationError):
    """
    Raised when an inactive user attempts to authenticate.
    """
    def __init__(self, extra: dict[str, Any] | None = None) -> None:
        super().__init__(
            message = "User account is inactive",
            extra = extra
        )


class ProgramNotFound(ResourceNotFound):
    """
    Raised when a program is not found
    """
    def __init__(
        self,
        identifier: str | int,
        extra: dict[str,
                    Any] | None = None,
    ) -> None:
        super().__init__(
            resource = "Program",
            identifier = identifier,
            extra = extra
        )


class SlugAlreadyExists(ConflictError):
    """
    Raised when attempting to create a program with existing slug
    """
    def __init__(
        self,
        slug: str,
        extra: dict[str,
                    Any] | None = None
    ) -> None:
        super().__init__(
            message = f"Program with slug '{slug}' already exists",
            extra = extra,
        )
        self.slug = slug


class AssetNotFound(ResourceNotFound):
    """
    Raised when an asset is not found
    """
    def __init__(
        self,
        identifier: str | int,
        extra: dict[str,
                    Any] | None = None,
    ) -> None:
        super().__init__(
            resource = "Asset",
            identifier = identifier,
            extra = extra
        )


class NotProgramOwner(PermissionDenied):
    """
    Raised when user tries to modify a program they don't own
    """
    def __init__(self, extra: dict[str, Any] | None = None) -> None:
        super().__init__(
            message = "You are not the owner of this program",
            extra = extra
        )


class ReportNotFound(ResourceNotFound):
    """
    Raised when a report is not found
    """
    def __init__(
        self,
        identifier: str | int,
        extra: dict[str,
                    Any] | None = None,
    ) -> None:
        super().__init__(
            resource = "Report",
            identifier = identifier,
            extra = extra
        )


class NotReportOwner(PermissionDenied):
    """
    Raised when user tries to modify a report they don't own
    """
    def __init__(self, extra: dict[str, Any] | None = None) -> None:
        super().__init__(
            message = "You are not the owner of this report",
            extra = extra
        )


class ProgramNotActive(ValidationError):
    """
    Raised when trying to submit to an inactive program
    """
    def __init__(self, extra: dict[str, Any] | None = None) -> None:
        super().__init__(
            message = "This program is not accepting submissions",
            extra = extra
        )


class CannotSubmitToOwnProgram(ValidationError):
    """
    Raised when user tries to submit a report to their own program
    """
    def __init__(self, extra: dict[str, Any] | None = None) -> None:
        super().__init__(
            message = "You cannot submit reports to your own program",
            extra = extra
        )


class InvalidStatusTransition(ValidationError):
    """
    Raised when an invalid status transition is attempted
    """
    def __init__(
        self,
        current: str,
        target: str,
        extra: dict[str,
                    Any] | None = None
    ) -> None:
        super().__init__(
            message = f"Cannot transition from '{current}' to '{target}'",
            extra = extra
        )
