"""
©AngelaMos | 2026
endpoint.py

endpoint() decorator for auth, role enforcement, and error boundary

Wraps route handlers with JWT extraction and user loading onto flask.g,
optional role checking against g.current_user.role, and a catch-all
exception handler that returns JSON 500 instead of an HTML traceback.

Key exports:
  endpoint - factory returning a decorator; params are auth_required and roles

Connects to:
  core/auth.py - calls decode_access_token, extract_bearer_token
  core/errors.py - raises AuthenticationError, ForbiddenError; catches AppError
  models/User.py - loads user by ID from JWT sub claim
  routes/ - applied to every route handler
"""

import functools
from typing import Any
from collections.abc import Callable, Sequence

import structlog
from flask import g, jsonify

from app.core.errors import AppError, AuthenticationError, ForbiddenError
from app.core.auth import decode_access_token, extract_bearer_token
from app.models.User import User


logger = structlog.get_logger()


def endpoint(
    auth_required: bool = True,
    roles: Sequence[str] | None = None,
) -> Callable[...,
              Any]:
    """
    Outermost decorator that provides auth extraction, role gating,
    and an error boundary
    """
    effective_auth = auth_required or roles is not None

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                _resolve_auth(effective_auth)
                if roles is not None:
                    _enforce_roles(roles)
                return fn(*args, **kwargs)
            except AppError:
                raise
            except Exception:
                logger.exception(
                    "unhandled_error",
                    endpoint = fn.__name__,
                )
                return jsonify({
                    "error": "InternalServerError",
                    "message": "Internal server error",
                }), 500

        return wrapper

    return decorator


def _resolve_auth(required: bool) -> None:
    """
    Extract JWT and load user onto flask g or raise if required
    """
    g.current_user = None
    token = extract_bearer_token()
    if not token:
        if required:
            raise AuthenticationError()
        return

    try:
        payload = decode_access_token(token)
    except Exception as exc:
        if required:
            raise AuthenticationError("Invalid or expired token") from exc
        return

    user = User.get_or_none(payload["sub"])
    if user is None:
        if required:
            raise AuthenticationError("User not found")
        return
    g.current_user = user


def _enforce_roles(allowed: Sequence[str]) -> None:
    """
    Verify the authenticated user holds one of the required roles
    """
    user = g.current_user
    if user is None or user.role not in allowed:
        raise ForbiddenError()
