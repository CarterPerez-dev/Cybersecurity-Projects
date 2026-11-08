"""
©AngelaMos | 2026
errors.py

Application exception hierarchy and Flask error handler registration

Defines AppError and subclasses (NotFoundError, ValidationError,
AuthenticationError, ForbiddenError, ConflictError), each carrying
an HTTP status code. register_error_handlers attaches JSON handlers
for all AppError subclasses plus 404, 405, and 500.

Key exports:
  AppError - base exception with status_code and message
  NotFoundError, ValidationError, AuthenticationError, ForbiddenError, ConflictError
  register_error_handlers - attaches handlers to the Flask app

Connects to:
  __init__.py - calls register_error_handlers
  models/Base.py - raises NotFoundError from get_by_id
  core/decorators/endpoint.py - catches AppError, raises auth and forbidden errors
  core/decorators/schema.py - raises ValidationError on Pydantic failure
"""

from typing import Any

from flask import Flask, jsonify


class AppError(Exception):
    """
    Base application error with HTTP status code
    """
    status_code: int = 500
    message: str = "Internal server error"

    def __init__(
        self,
        message: str | None = None,
        status_code: int | None = None,
    ) -> None:
        super().__init__(message or self.message)
        if message:
            self.message = message
        if status_code:
            self.status_code = status_code


class NotFoundError(AppError):
    """
    Raised when a requested resource does not exist
    """
    status_code = 404
    message = "Resource not found"


class ValidationError(AppError):
    """
    Raised when input data fails validation
    """
    status_code = 422
    message = "Validation failed"

    def __init__(
        self,
        message: str | None = None,
        errors: list[dict[str,
                          Any]] | None = None,
    ) -> None:
        super().__init__(message)
        self.errors = errors or []


class AuthenticationError(AppError):
    """
    Raised when a request lacks valid credentials
    """
    status_code = 401
    message = "Authentication required"


class ForbiddenError(AppError):
    """
    Raised when an authenticated user lacks permission
    """
    status_code = 403
    message = "Insufficient permissions"


class ConflictError(AppError):
    """
    Raised when a resource already exists or conflicts
    """
    status_code = 409
    message = "Resource already exists"


def register_error_handlers(app: Flask) -> None:
    """
    Attach JSON error handlers to the Flask app
    """
    @app.errorhandler(AppError)
    def handle_app_error(error: AppError):  # type: ignore[no-untyped-def]
        payload: dict[str,
                      Any] = {
                          "error": type(error).__name__,
                          "message": error.message,
                      }
        if isinstance(error, ValidationError) and error.errors:
            payload["details"] = error.errors
        return jsonify(payload), error.status_code

    @app.errorhandler(404)
    def handle_404(error):  # type: ignore[no-untyped-def]
        return jsonify({
            "error": "NotFound",
            "message": "Endpoint not found",
        }), 404

    @app.errorhandler(405)
    def handle_405(error):  # type: ignore[no-untyped-def]
        return jsonify({
            "error": "MethodNotAllowed",
            "message": "Method not allowed",
        }), 405

    @app.errorhandler(500)
    def handle_500(error):  # type: ignore[no-untyped-def]
        return jsonify({
            "error": "InternalServerError",
            "message": "Internal server error",
        }), 500
