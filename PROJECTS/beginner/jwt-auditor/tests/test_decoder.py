"""Tests for the raw JWT decoding layer."""

import pytest

from jwt_auditor.decoder import InvalidTokenError, decode
from tests.conftest import build_hs_token, build_none_token


def test_decode_returns_header_and_payload() -> None:
    token = build_hs_token({"sub": "alice", "role": "user"})
    parsed = decode(token)
    assert parsed.header["alg"] == "HS256"
    assert parsed.header["typ"] == "JWT"
    assert parsed.payload["sub"] == "alice"
    assert parsed.payload["role"] == "user"


def test_algorithm_property_reads_header() -> None:
    parsed = decode(build_hs_token({"sub": "x"}, alg = "HS512"))
    assert parsed.algorithm == "HS512"


def test_none_token_has_empty_signature() -> None:
    parsed = decode(build_none_token({"sub": "x"}))
    assert parsed.signature == b""
    assert parsed.signature_b64 == ""
    assert parsed.algorithm == "none"


def test_signing_input_is_header_dot_payload() -> None:
    token = build_hs_token({"sub": "x"})
    parsed = decode(token)
    expected = ".".join(token.split(".")[: 2]).encode("ascii")
    assert parsed.signing_input == expected


def test_whitespace_is_stripped() -> None:
    token = build_hs_token({"sub": "x"})
    assert decode(f"  {token}\n").payload["sub"] == "x"


def test_empty_string_is_rejected() -> None:
    with pytest.raises(InvalidTokenError):
        decode("   ")


@pytest.mark.parametrize("bad", ["only-one-part", "two.parts", "a.b.c.d"])
def test_wrong_segment_count_is_rejected(bad: str) -> None:
    with pytest.raises(InvalidTokenError):
        decode(bad)


def test_non_base64_header_is_rejected() -> None:
    with pytest.raises(InvalidTokenError):
        decode("!!!.@@@.###")


def test_header_that_is_not_json_object_is_rejected() -> None:
    # base64url of the JSON string "hello" (a string, not an object)
    import base64

    seg = base64.urlsafe_b64encode(b'"hello"').rstrip(b"=").decode()
    with pytest.raises(InvalidTokenError):
        decode(f"{seg}.{seg}.{seg}")
