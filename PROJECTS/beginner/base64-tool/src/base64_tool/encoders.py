"""
©AngelaMos | 2026
encoders.py

Encode and decode functions for all five supported formats

Provides individual encode/decode functions for base64, base64url,
base32, hex, and URL percent-encoding, plus a dispatch registry
(ENCODER_REGISTRY) that maps each EncodingFormat to its function pair.
The top-level encode(), decode(), and try_decode() functions route
calls through the registry and handle all common decoding exceptions.

Key exports:
  encode() - Encode bytes to string for a given format
  decode() - Decode string to bytes for a given format
  try_decode() - Like decode() but returns None on failure instead of raising
  ENCODER_REGISTRY - Dict mapping EncodingFormat to (encoder, decoder) function pairs
  EncoderFn, DecoderFn - Type aliases for encoder and decoder callables

Connects to:
  constants.py - imports EncodingFormat
  detector.py - imports try_decode
  cli.py - imports encode, decode, encode_url, decode_url
  test_encoders.py - tests all functions directly
  test_properties.py - property-based roundtrip tests
  test_peeler.py - imports encode to build test inputs
"""

import base64 as b64
import binascii
from collections.abc import Callable
from urllib.parse import (
    quote,
    quote_plus,
    unquote,
    unquote_plus,
)
from base64_tool.constants import EncodingFormat


type EncoderFn = Callable[[bytes], str]
type DecoderFn = Callable[[str], bytes]


def encode_base64(data: bytes) -> str:
    return b64.b64encode(data).decode("ascii")


def decode_base64(data: str) -> bytes:
    cleaned = "".join(data.split())
    return b64.b64decode(cleaned, validate = True)


def encode_base64url(data: bytes) -> str:
    return b64.urlsafe_b64encode(data).decode("ascii")


def decode_base64url(data: str) -> bytes:
    cleaned = "".join(data.split())
    return b64.urlsafe_b64decode(cleaned)


def encode_base32(data: bytes) -> str:
    return b64.b32encode(data).decode("ascii")


def decode_base32(data: str) -> bytes:
    cleaned = "".join(data.split()).upper()
    return b64.b32decode(cleaned)


def encode_hex(data: bytes) -> str:
    return data.hex()


def decode_hex(data: str) -> bytes:
    cleaned = data.strip()
    for sep in (" ", ":", "-", "."):
        cleaned = cleaned.replace(sep, "")
    return bytes.fromhex(cleaned)


def encode_url(data: bytes, *, form: bool = False) -> str:
    text = data.decode("utf-8")
    if form:
        return quote_plus(text)
    return quote(text, safe = "")


def decode_url(data: str, *, form: bool = False) -> bytes:
    if form:
        return unquote_plus(data).encode("utf-8")
    return unquote(data).encode("utf-8")


ENCODER_REGISTRY: dict[
    EncodingFormat,
    tuple[EncoderFn,
          DecoderFn],
] = {
    EncodingFormat.BASE64: (encode_base64,
                            decode_base64),
    EncodingFormat.BASE64URL: (encode_base64url,
                               decode_base64url),
    EncodingFormat.BASE32: (encode_base32,
                            decode_base32),
    EncodingFormat.HEX: (encode_hex,
                         decode_hex),
    EncodingFormat.URL: (
        lambda data: encode_url(data),
        lambda data: decode_url(data),
    ),
}


def encode(data: bytes, fmt: EncodingFormat) -> str:
    encoder_fn, _ = ENCODER_REGISTRY[fmt]
    return encoder_fn(data)


def decode(data: str, fmt: EncodingFormat) -> bytes:
    _, decoder_fn = ENCODER_REGISTRY[fmt]
    return decoder_fn(data)


def try_decode(data: str, fmt: EncodingFormat) -> bytes | None:
    try:
        return decode(data, fmt)
    except (
            ValueError,
            binascii.Error,
            UnicodeDecodeError,
            UnicodeEncodeError,
    ):
        return None
