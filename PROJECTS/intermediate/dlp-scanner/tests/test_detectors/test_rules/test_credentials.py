"""
©AngelaMos | 2026
test_credentials.py
"""


import pytest

from dlp_scanner.detectors.rules.credentials import (
    AWS_ACCESS_KEY_PATTERN,
    GITHUB_CLASSIC_PAT_PATTERN,
    GITHUB_FINE_GRAINED_PATTERN,
    JWT_PATTERN,
    STRIPE_KEY_PATTERN,
    SLACK_TOKEN_PATTERN,
    PRIVATE_KEY_PATTERN,
    GENERIC_API_KEY_PATTERN,
)


class TestAWSAccessKey:
    def test_long_term_key_matches(self) -> None:
        assert (
            AWS_ACCESS_KEY_PATTERN.search("AKIAIOSFODNN7EXAMPLE")
            is not None
        )

    def test_session_key_matches(self) -> None:
        assert (
            AWS_ACCESS_KEY_PATTERN.search("ASIAQWERTYUIOP123456")
            is not None
        )

    def test_invalid_prefix_rejected(self) -> None:
        assert (
            AWS_ACCESS_KEY_PATTERN.search("ABCDIOSFODNN7EXAMPLE") is None
        )


class TestGitHubTokens:
    def test_classic_pat_matches(self) -> None:
        token = "ghp_" + "a" * 36
        assert (GITHUB_CLASSIC_PAT_PATTERN.search(token) is not None)

    def test_fine_grained_pat_matches(self) -> None:
        token = "github_pat_" + "a" * 22 + "_" + "b" * 59
        assert (GITHUB_FINE_GRAINED_PATTERN.search(token) is not None)

    def test_invalid_prefix_rejected(self) -> None:
        assert (
            GITHUB_CLASSIC_PAT_PATTERN.search("xyz_" + "a" * 36) is None
        )


class TestJWT:
    def test_jwt_matches(self) -> None:
        token = (
            "eyJhbGciOiJIUzI1NiJ9"
            ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
            ".abc123def456"
        )
        assert JWT_PATTERN.search(token) is not None

    def test_non_jwt_rejected(self) -> None:
        assert (JWT_PATTERN.search("not.a.jwt.token") is None)


class TestStripeKey:
    @pytest.mark.parametrize(
        "key",
        [
            "sk_test_" + "a" * 24,
            "sk_live_" + "b" * 24,
            "pk_test_" + "c" * 24,
            "pk_live_" + "d" * 30,
        ],
    )
    def test_stripe_keys_match(self, key: str) -> None:
        assert STRIPE_KEY_PATTERN.search(key) is not None

    def test_invalid_stripe_key(self) -> None:
        assert (STRIPE_KEY_PATTERN.search("sk_invalid_abc") is None)


class TestSlackToken:
    @pytest.mark.parametrize(
        "token",
        [
            "xoxb-" + "a" * 20,
            "xoxp-" + "b" * 30,
            "xoxa-" + "c" * 15,
        ],
    )
    def test_slack_tokens_match(self, token: str) -> None:
        assert (SLACK_TOKEN_PATTERN.search(token) is not None)


class TestPrivateKey:
    @pytest.mark.parametrize(
        "header",
        [
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
        ],
    )
    def test_private_key_headers_match(self, header: str) -> None:
        assert (PRIVATE_KEY_PATTERN.search(header) is not None)


class TestGenericAPIKey:
    @pytest.mark.parametrize(
        "text",
        [
            'api_key = "abcdef1234567890abcdef"',
            "API_KEY: abcdef1234567890abcdef",
            "secret_key='very_secret_key_value_12345'",
            'access_key = "abc123def456ghi789jkl012"',
        ],
    )
    def test_generic_api_keys_match(self, text: str) -> None:
        assert (GENERIC_API_KEY_PATTERN.search(text) is not None)
