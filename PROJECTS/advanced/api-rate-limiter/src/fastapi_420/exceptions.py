"""
ⒸAngelaMos | 2025
exceptions.py
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import HTTPException

from fastapi_420.types import Layer, StorageType

if TYPE_CHECKING:
    from fastapi_420.types import RateLimitResult


HTTP_420_ENHANCE_YOUR_CALM = 420


class RateLimitError(Exception):
    """
    Base exception for rate limiting errors
    """
    def __init__(
        self,
        message: str,
        details: dict[str,
                      Any] | None = None
    ) -> None:
        self.message = message
        self.details = details or {}
        super().__init__(self.message)


class EnhanceYourCalm(HTTPException):
    """
    HTTP 420 response - the signature rate limit response
    """
    def __init__(
        self,
        result: RateLimitResult | None = None,
        message: str = "Enhance your calm",
        detail: str = "Rate limit exceeded. Take a breather.",
        headers: dict[str,
                      str] | None = None,
    ) -> None:
        final_headers = {}
        if result:
            final_headers.update(result.headers)
        if headers:
            final_headers.update(headers)

        super().__init__(
            status_code = HTTP_420_ENHANCE_YOUR_CALM,
            detail = {
                "message": message,
                "detail": detail,
                "limit_info": result.headers if result else {}
            },
            headers = final_headers if final_headers else None,
        )
        self.result = result


class RateLimitExceeded(RateLimitError):
    """
    Raised when a rate limit is exceeded at any layer
    """
    def __init__(
        self,
        result: RateLimitResult,
        layer: Layer = Layer.USER,
        endpoint: str = "",
        identifier: str = "",
    ) -> None:
        self.result = result
        self.layer = layer
        self.endpoint = endpoint
        self.identifier = identifier
        super().__init__(
            message = f"Rate limit exceeded on {layer.value} layer",
            details = {
                "layer": layer.value,
                "endpoint": endpoint,
                "remaining": result.remaining,
                "reset_after": result.reset_after,
            },
        )


class StorageError(RateLimitError):
    """
    Raised when storage backend operations fail
    """
    def __init__(
        self,
        operation: str,
        backend: StorageType | None = None,
        original_error: Exception | None = None,
    ) -> None:
        self.operation = operation
        self.backend = backend
        self.original_error = original_error
        backend_name = backend.value if backend else "unknown"
        super().__init__(
            message =
            f"Storage operation '{operation}' failed on {backend_name}",
            details = {
                "operation": operation,
                "backend": backend_name,
                "error": str(original_error) if original_error else None,
            },
        )


class StorageConnectionError(StorageError):
    """
    Raised when unable to connect to storage backend
    """
    def __init__(
        self,
        backend: StorageType,
        original_error: Exception | None = None,
    ) -> None:
        super().__init__(
            operation = "connect",
            backend = backend,
            original_error = original_error,
        )


class StorageUnavailable(StorageError):
    """
    Raised when storage backend is temporarily unavailable
    """
    def __init__(
        self,
        backend: StorageType,
        original_error: Exception | None = None,
    ) -> None:
        super().__init__(
            operation = "health_check",
            backend = backend,
            original_error = original_error,
        )


class FingerprintError(RateLimitError):
    """
    Raised when fingerprint extraction fails
    """
    def __init__(
        self,
        reason: str,
        original_error: Exception | None = None,
    ) -> None:
        self.reason = reason
        self.original_error = original_error
        super().__init__(
            message = f"Fingerprint extraction failed: {reason}",
            details = {
                "reason": reason,
                "error": str(original_error) if original_error else None,
            },
        )


class CircuitBreakerOpen(RateLimitError):
    """
    Raised when global circuit breaker is open
    """
    def __init__(
        self,
        recovery_time: float,
        total_requests: int,
        threshold: int,
    ) -> None:
        self.recovery_time = recovery_time
        self.total_requests = total_requests
        self.threshold = threshold
        super().__init__(
            message = "Circuit breaker is open - API is in defense mode",
            details = {
                "recovery_time": recovery_time,
                "total_requests": total_requests,
                "threshold": threshold,
            },
        )


class ConfigurationError(RateLimitError):
    """
    Raised when rate limiter configuration is invalid
    """
    def __init__(self, reason: str) -> None:
        super().__init__(
            message = f"Invalid configuration: {reason}",
            details = {"reason": reason},
        )


class InvalidRuleError(ConfigurationError):
    """
    Raised when a rate limit rule string is invalid
    """
    def __init__(self, rule_string: str, reason: str) -> None:
        self.rule_string = rule_string
        super().__init__(
            reason = f"Invalid rule '{rule_string}': {reason}"
        )
