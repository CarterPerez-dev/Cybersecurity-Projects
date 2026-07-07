"""
Shared test helpers for building JWTs.

Tokens are built with the project's own hmac_sign so the tests exercise the
real signing path and stay dependency free. A fixed clock is exposed so the
time based checks are deterministic.
"""

import base64
import json
from typing import Any

import pytest

from jwt_auditor.signatures import hmac_sign

# A fixed "now" used across time based tests: 2026-01-01 00:00:00 UTC.
FIXED_NOW = 1767225600.0
ONE_HOUR = 3600.0
ONE_DAY = 86400.0


def b64url(data: bytes) -> str:
    """Encode bytes as base64url without padding, the way JWT does."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _segment(obj: dict[str, Any]) -> str:
    """Encode a JSON object as a base64url JWT segment."""
    return b64url(json.dumps(obj, separators = (",", ":")).encode("utf-8"))


def build_hs_token(
    payload: dict[str,
                  Any],
    secret: str = "secret",
    alg: str = "HS256",
    header: dict[str,
                 Any] | None = None,
) -> str:
    """Build an HMAC signed token using the given secret."""
    head = header or {"alg": alg, "typ": "JWT"}
    signing_input = f"{_segment(head)}.{_segment(payload)}".encode("ascii")
    signature = hmac_sign(signing_input, secret.encode("utf-8"), alg)
    return f"{_segment(head)}.{_segment(payload)}.{b64url(signature)}"


def build_none_token(payload: dict[str, Any]) -> str:
    """Build an unsigned alg none token ending in a trailing dot."""
    head = {"alg": "none", "typ": "JWT"}
    return f"{_segment(head)}.{_segment(payload)}."


def build_unsigned_token(payload: dict[str, Any], alg: str = "HS256") -> str:
    """Build a token that declares a real alg but carries no signature."""
    head = {"alg": alg, "typ": "JWT"}
    return f"{_segment(head)}.{_segment(payload)}."


def build_bare_alg_token(payload: dict[str, Any], alg: str) -> str:
    """Build a token with an arbitrary alg and a dummy signature segment."""
    head = {"alg": alg, "typ": "JWT"}
    return f"{_segment(head)}.{_segment(payload)}.{b64url(b'dummy-signature')}"


@pytest.fixture
def now() -> float:
    """The fixed clock value for deterministic time checks."""
    return FIXED_NOW
