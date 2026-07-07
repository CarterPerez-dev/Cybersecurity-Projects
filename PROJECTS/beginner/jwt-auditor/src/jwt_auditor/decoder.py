"""
decoder.py

Splits a JWT into its three parts and decodes the header and payload.

A JWS-style JWT is three base64url segments joined by dots:
header.payload.signature. This module does the raw decoding only. It never
checks the signature and never trusts the "alg" field. That separation is
deliberate. A decoder that quietly validates is how people end up trusting
tokens they should not.

Key exports:
  DecodedToken - dataclass holding the parsed pieces
  decode - parse a token string into a DecodedToken
  InvalidTokenError - raised when the string is not a well formed JWT

Connects to:
  checks.py - runs security checks against a DecodedToken
  signatures.py - uses signing_input and signature to test secrets
"""

import base64
import binascii
import json
from dataclasses import dataclass
from typing import Any


class InvalidTokenError(ValueError):
    """Raised when a string cannot be parsed as a JWT."""


def _b64url_decode(segment: str) -> bytes:
    """
    Decode a base64url segment, adding the padding JWT strips off.

    JWT drops the trailing "=" padding to keep tokens compact (RFC 7515
    calls this base64url without padding). We add it back before handing
    the bytes to the standard decoder, otherwise it rejects the input.
    """
    padding = "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(segment + padding)
    except (binascii.Error, ValueError) as exc:
        raise InvalidTokenError(
            f"segment is not valid base64url: {exc}"
        ) from None


def _decode_json_segment(segment: str, name: str) -> dict[str, Any]:
    """Decode a base64url segment and parse it as a JSON object."""
    raw = _b64url_decode(segment)
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise InvalidTokenError(f"{name} is not valid JSON: {exc}") from None
    if not isinstance(value, dict):
        raise InvalidTokenError(
            f"{name} must be a JSON object, got {type(value).__name__}"
        )
    return value


@dataclass
class DecodedToken:
    """
    The decoded pieces of a JWT.

    signing_input is the exact bytes a signature is computed over
    (the header and payload segments joined by a dot, ASCII encoded).
    Keeping it here means the signature code never has to re-derive it.
    """

    raw: str
    header: dict[str, Any]
    payload: dict[str, Any]
    signature: bytes
    signing_input: bytes
    header_b64: str
    payload_b64: str
    signature_b64: str

    @property
    def algorithm(self) -> str:
        """Return the declared alg header, or an empty string if absent."""
        alg = self.header.get("alg", "")
        return alg if isinstance(alg, str) else str(alg)


def decode(token: str) -> DecodedToken:
    """
    Parse a JWT string into its decoded parts without verifying it.

    Raises InvalidTokenError if the string does not have three segments or
    if the header/payload are not base64url encoded JSON objects. An empty
    signature segment (alg none tokens end with a trailing dot) is allowed
    here on purpose so the checks can flag it.
    """
    token = token.strip()
    if not token:
        raise InvalidTokenError("token is empty")

    segments = token.split(".")
    if len(segments) != 3:
        raise InvalidTokenError(
            f"a JWT has 3 dot separated segments, this has {len(segments)}"
        )

    header_b64, payload_b64, signature_b64 = segments
    header = _decode_json_segment(header_b64, "header")
    payload = _decode_json_segment(payload_b64, "payload")
    signature = _b64url_decode(signature_b64) if signature_b64 else b""

    return DecodedToken(
        raw = token,
        header = header,
        payload = payload,
        signature = signature,
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii"),
        header_b64 = header_b64,
        payload_b64 = payload_b64,
        signature_b64 = signature_b64,
    )
