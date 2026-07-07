"""Tests for HMAC signing, verification, cracking, and key confusion."""

import hashlib
import hmac

from jwt_auditor.decoder import decode
from jwt_auditor.signatures import (
    crack_hmac_secret,
    hmac_sign,
    key_confusion_secret,
    supported_hmac_algs,
    verify_hmac,
)
from tests.conftest import build_bare_alg_token, build_hs_token

# A stand in "public key" for the confusion test. Any non secret bytes work.
FAKE_PUBLIC_KEY = b"-----BEGIN PUBLIC KEY-----\nMFkwEwYHfake\n-----END PUBLIC KEY-----\n"


def test_supported_algs() -> None:
    assert supported_hmac_algs() == {"HS256", "HS384", "HS512"}


def test_hmac_sign_matches_stdlib() -> None:
    signing_input = b"header.payload"
    expected = hmac.new(b"secret", signing_input, hashlib.sha256).digest()
    assert hmac_sign(signing_input, b"secret", "HS256") == expected


def test_verify_hmac_accepts_correct_secret() -> None:
    token = decode(build_hs_token({"sub": "x"}, secret = "hunter2"))
    assert verify_hmac(token, b"hunter2") is True


def test_verify_hmac_rejects_wrong_secret() -> None:
    token = decode(build_hs_token({"sub": "x"}, secret = "hunter2"))
    assert verify_hmac(token, b"wrong") is False


def test_verify_hmac_rejects_non_hmac_alg() -> None:
    token = decode(build_bare_alg_token({"sub": "x"}, alg = "RS256"))
    assert verify_hmac(token, b"anything") is False


def test_crack_finds_secret_in_list() -> None:
    token = decode(build_hs_token({"sub": "x"}, secret = "changeme"))
    assert crack_hmac_secret(token, ["nope", "changeme", "other"]) == "changeme"


def test_crack_returns_none_when_absent() -> None:
    token = decode(
        build_hs_token({"sub": "x"},
                       secret = "a-very-strong-random-key")
    )
    assert crack_hmac_secret(token, ["nope", "other"]) is None


def test_crack_returns_none_for_non_hmac() -> None:
    token = decode(build_bare_alg_token({"sub": "x"}, alg = "RS256"))
    assert crack_hmac_secret(token, ["secret", "changeme"]) is None


def test_key_confusion_detects_public_key_as_secret() -> None:
    # Attacker forges an HS256 token signed with the public key bytes.
    forged = build_hs_token(
        {"sub": "admin"},
        secret = FAKE_PUBLIC_KEY.decode("latin-1"),
        alg = "HS256",
    )
    token = decode(forged)
    result = key_confusion_secret(token, FAKE_PUBLIC_KEY)
    assert result is not None
    assert "verified as HS256" in result


def test_key_confusion_returns_none_for_unrelated_key() -> None:
    token = decode(build_hs_token({"sub": "x"}, secret = "unrelated-secret"))
    assert key_confusion_secret(token, FAKE_PUBLIC_KEY) is None
