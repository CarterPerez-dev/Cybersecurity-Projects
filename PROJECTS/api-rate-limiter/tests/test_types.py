"""
ⒸAngelaMos | 2025
test_types.py
"""
from __future__ import annotations

import pytest

from fastapi_420.types import (
    Algorithm,
    CircuitState,
    DefenseContext,
    DefenseMode,
    FingerprintData,
    FingerprintLevel,
    Layer,
    RateLimitKey,
    RateLimitResult,
    RateLimitRule,
    StorageType,
    TokenBucketState,
    WindowState,
)

from tests.conftest import (
    KEY_PREFIX,
    KEY_VERSION,
    TEST_ENDPOINT,
    TEST_IP_V4,
    TEST_USER_AGENT,
    WINDOW_DAY,
    WINDOW_HOUR,
    WINDOW_MINUTE,
    WINDOW_SECOND,
    CircuitStateFactory,
    DefenseContextFactory,
    FingerprintFactory,
    KeyFactory,
    ResultFactory,
    RuleFactory,
    TokenBucketStateFactory,
    WindowStateFactory,
)


class TestAlgorithmEnum:
    """
    Tests for Algorithm enum values
    """
    def test_sliding_window_value(self) -> None:
        assert Algorithm.SLIDING_WINDOW.value == "sliding_window"

    def test_token_bucket_value(self) -> None:
        assert Algorithm.TOKEN_BUCKET.value == "token_bucket"

    def test_fixed_window_value(self) -> None:
        assert Algorithm.FIXED_WINDOW.value == "fixed_window"

    def test_leaky_bucket_value(self) -> None:
        assert Algorithm.LEAKY_BUCKET.value == "leaky_bucket"

    def test_enum_is_str_enum(self) -> None:
        assert isinstance(Algorithm.SLIDING_WINDOW, str)
        assert Algorithm.SLIDING_WINDOW == "sliding_window"


class TestFingerprintLevelEnum:
    """
    Tests for FingerprintLevel enum values
    """
    def test_strict_value(self) -> None:
        assert FingerprintLevel.STRICT.value == "strict"

    def test_normal_value(self) -> None:
        assert FingerprintLevel.NORMAL.value == "normal"

    def test_relaxed_value(self) -> None:
        assert FingerprintLevel.RELAXED.value == "relaxed"

    def test_custom_value(self) -> None:
        assert FingerprintLevel.CUSTOM.value == "custom"


class TestDefenseModeEnum:
    """
    Tests for DefenseMode enum values
    """
    def test_adaptive_value(self) -> None:
        assert DefenseMode.ADAPTIVE.value == "adaptive"

    def test_lockdown_value(self) -> None:
        assert DefenseMode.LOCKDOWN.value == "lockdown"

    def test_challenge_value(self) -> None:
        assert DefenseMode.CHALLENGE.value == "challenge"

    def test_disabled_value(self) -> None:
        assert DefenseMode.DISABLED.value == "disabled"


class TestStorageTypeEnum:
    """
    Tests for StorageType enum values
    """
    def test_redis_value(self) -> None:
        assert StorageType.REDIS.value == "redis"

    def test_memory_value(self) -> None:
        assert StorageType.MEMORY.value == "memory"


class TestLayerEnum:
    """
    Tests for Layer enum values
    """
    def test_user_value(self) -> None:
        assert Layer.USER.value == "user"

    def test_endpoint_value(self) -> None:
        assert Layer.ENDPOINT.value == "endpoint"

    def test_global_value(self) -> None:
        assert Layer.GLOBAL.value == "global"


class TestRateLimitRule:
    """
    Tests for RateLimitRule dataclass and parsing
    """
    def test_create_valid_rule(self) -> None:
        rule = RateLimitRule(requests = 100, window_seconds = 60)
        assert rule.requests == 100
        assert rule.window_seconds == 60

    def test_invalid_requests_zero(self) -> None:
        with pytest.raises(ValueError,
                           match = "requests must be positive"):
            RateLimitRule(requests = 0, window_seconds = 60)

    def test_invalid_requests_negative(self) -> None:
        with pytest.raises(ValueError,
                           match = "requests must be positive"):
            RateLimitRule(requests = -1, window_seconds = 60)

    def test_invalid_window_zero(self) -> None:
        with pytest.raises(ValueError,
                           match = "window_seconds must be positive"):
            RateLimitRule(requests = 100, window_seconds = 0)

    def test_invalid_window_negative(self) -> None:
        with pytest.raises(ValueError,
                           match = "window_seconds must be positive"):
            RateLimitRule(requests = 100, window_seconds = -1)

    def test_parse_per_second(self) -> None:
        for unit in ["second", "seconds", "sec", "s"]:
            rule = RateLimitRule.parse(f"10/{unit}")
            assert rule.requests == 10
            assert rule.window_seconds == WINDOW_SECOND

    def test_parse_per_minute(self) -> None:
        for unit in ["minute", "minutes", "min", "m"]:
            rule = RateLimitRule.parse(f"100/{unit}")
            assert rule.requests == 100
            assert rule.window_seconds == WINDOW_MINUTE

    def test_parse_per_hour(self) -> None:
        for unit in ["hour", "hours", "hr", "h"]:
            rule = RateLimitRule.parse(f"1000/{unit}")
            assert rule.requests == 1000
            assert rule.window_seconds == WINDOW_HOUR

    def test_parse_per_day(self) -> None:
        for unit in ["day", "days", "d"]:
            rule = RateLimitRule.parse(f"10000/{unit}")
            assert rule.requests == 10000
            assert rule.window_seconds == WINDOW_DAY

    def test_parse_with_whitespace(self) -> None:
        rule = RateLimitRule.parse("  100 / minute  ")
        assert rule.requests == 100
        assert rule.window_seconds == WINDOW_MINUTE

    def test_parse_case_insensitive(self) -> None:
        rule = RateLimitRule.parse("100/MINUTE")
        assert rule.requests == 100
        assert rule.window_seconds == WINDOW_MINUTE

    def test_parse_invalid_format_no_slash(self) -> None:
        with pytest.raises(ValueError,
                           match = "Invalid rate limit format"):
            RateLimitRule.parse("100minute")

    def test_parse_invalid_format_multiple_slashes(self) -> None:
        with pytest.raises(ValueError,
                           match = "Invalid rate limit format"):
            RateLimitRule.parse("100/per/minute")

    def test_parse_invalid_request_count(self) -> None:
        with pytest.raises(ValueError, match = "Invalid request count"):
            RateLimitRule.parse("abc/minute")

    def test_parse_unknown_time_unit(self) -> None:
        with pytest.raises(ValueError, match = "Unknown time unit"):
            RateLimitRule.parse("100/fortnight")

    def test_str_representation_second(self) -> None:
        rule = RateLimitRule(requests = 10, window_seconds = 1)
        assert str(rule) == "10/second"

    def test_str_representation_minute(self) -> None:
        rule = RateLimitRule(requests = 100, window_seconds = 60)
        assert str(rule) == "100/minute"

    def test_str_representation_hour(self) -> None:
        rule = RateLimitRule(requests = 1000, window_seconds = 3600)
        assert str(rule) == "1000/hour"

    def test_str_representation_day(self) -> None:
        rule = RateLimitRule(requests = 10000, window_seconds = 86400)
        assert str(rule) == "10000/day"

    def test_str_representation_custom_window(self) -> None:
        rule = RateLimitRule(requests = 50, window_seconds = 120)
        assert str(rule) == "50/120s"

    def test_frozen_immutable(self) -> None:
        rule = RateLimitRule(requests = 100, window_seconds = 60)
        with pytest.raises(AttributeError):
            rule.requests = 200

    def test_factory_create(self) -> None:
        rule = RuleFactory.create()
        assert rule.requests == 100
        assert rule.window_seconds == WINDOW_MINUTE

    def test_factory_per_second(self) -> None:
        rule = RuleFactory.per_second(10)
        assert rule.requests == 10
        assert rule.window_seconds == WINDOW_SECOND

    def test_factory_strict(self) -> None:
        rule = RuleFactory.strict()
        assert rule.requests == 10
        assert rule.window_seconds == WINDOW_MINUTE


class TestRateLimitResult:
    """
    Tests for RateLimitResult dataclass and headers
    """
    def test_allowed_result(self) -> None:
        result = RateLimitResult(
            allowed = True,
            limit = 100,
            remaining = 50,
            reset_after = 30.0,
        )
        assert result.allowed is True
        assert result.limit == 100
        assert result.remaining == 50
        assert result.reset_after == 30.0
        assert result.retry_after is None

    def test_denied_result(self) -> None:
        result = RateLimitResult(
            allowed = False,
            limit = 100,
            remaining = 0,
            reset_after = 60.0,
            retry_after = 60.0,
        )
        assert result.allowed is False
        assert result.remaining == 0
        assert result.retry_after == 60.0

    def test_headers_basic(self) -> None:
        result = RateLimitResult(
            allowed = True,
            limit = 100,
            remaining = 50,
            reset_after = 30.5,
        )
        headers = result.headers
        assert headers["RateLimit-Limit"] == "100"
        assert headers["RateLimit-Remaining"] == "50"
        assert headers["RateLimit-Reset"] == "30"
        assert "Retry-After" not in headers

    def test_headers_with_retry_after(self) -> None:
        result = RateLimitResult(
            allowed = False,
            limit = 100,
            remaining = 0,
            reset_after = 60.0,
            retry_after = 45.5,
        )
        headers = result.headers
        assert headers["Retry-After"] == "45"

    def test_headers_remaining_never_negative(self) -> None:
        result = RateLimitResult(
            allowed = False,
            limit = 100,
            remaining = -5,
            reset_after = 60.0,
        )
        headers = result.headers
        assert headers["RateLimit-Remaining"] == "0"

    def test_frozen_immutable(self) -> None:
        result = ResultFactory.allowed()
        with pytest.raises(AttributeError):
            result.allowed = False

    def test_factory_allowed(self) -> None:
        result = ResultFactory.allowed(limit = 200, remaining = 150)
        assert result.allowed is True
        assert result.limit == 200
        assert result.remaining == 150

    def test_factory_denied(self) -> None:
        result = ResultFactory.denied(retry_after = 30.0)
        assert result.allowed is False
        assert result.remaining == 0
        assert result.retry_after == 30.0

    def test_factory_near_limit(self) -> None:
        result = ResultFactory.near_limit(remaining = 2)
        assert result.allowed is True
        assert result.remaining == 2


class TestFingerprintData:
    """
    Tests for FingerprintData and composite key generation
    """
    def test_create_full_fingerprint(self) -> None:
        fp = FingerprintData(
            ip = TEST_IP_V4,
            ip_normalized = TEST_IP_V4,
            user_agent = TEST_USER_AGENT,
            accept_language = "en-US",
            accept_encoding = "gzip",
            headers_hash = "abc123",
            auth_identifier = "user_456",
            tls_fingerprint = "ja3hash",
            geo_asn = "AS12345",
        )
        assert fp.ip == TEST_IP_V4
        assert fp.user_agent == TEST_USER_AGENT
        assert fp.auth_identifier == "user_456"

    def test_create_minimal_fingerprint(self) -> None:
        fp = FingerprintData(ip = TEST_IP_V4, ip_normalized = TEST_IP_V4)
        assert fp.ip == TEST_IP_V4
        assert fp.user_agent is None
        assert fp.auth_identifier is None

    def test_composite_key_relaxed_ip_only(self) -> None:
        fp = FingerprintFactory.anonymous()
        key = fp.to_composite_key(FingerprintLevel.RELAXED)
        assert key == TEST_IP_V4

    def test_composite_key_relaxed_with_auth(self) -> None:
        fp = FingerprintFactory.create(auth_identifier = "user_123")
        key = fp.to_composite_key(FingerprintLevel.RELAXED)
        assert "user_123" in key
        assert TEST_IP_V4 in key

    def test_composite_key_normal(self) -> None:
        fp = FingerprintFactory.create(auth_identifier = "user_123")
        key = fp.to_composite_key(FingerprintLevel.NORMAL)
        parts = key.split(":")
        assert len(parts) == 3
        assert parts[0] == TEST_IP_V4
        assert TEST_USER_AGENT in parts[1]
        assert parts[2] == "user_123"

    def test_composite_key_strict(self) -> None:
        fp = FingerprintData(
            ip = TEST_IP_V4,
            ip_normalized = TEST_IP_V4,
            user_agent = TEST_USER_AGENT,
            accept_language = "en-US",
            accept_encoding = "gzip",
            headers_hash = "abc123",
            auth_identifier = "user_456",
            tls_fingerprint = "ja3hash",
            geo_asn = "AS12345",
        )
        key = fp.to_composite_key(FingerprintLevel.STRICT)
        parts = key.split(":")
        assert len(parts) == 8
        assert parts[0] == TEST_IP_V4

    def test_factory_authenticated(self) -> None:
        fp = FingerprintFactory.authenticated(auth_id = "testuser")
        assert fp.auth_identifier is not None
        assert len(fp.auth_identifier) == 16

    def test_factory_minimal(self) -> None:
        fp = FingerprintFactory.minimal()
        assert fp.ip == TEST_IP_V4
        assert fp.user_agent is None


class TestWindowState:
    """
    Tests for WindowState and weighted count calculation
    """
    def test_create_empty_state(self) -> None:
        state = WindowState()
        assert state.current_count == 0
        assert state.previous_count == 0

    def test_weighted_count_start_of_window(self) -> None:
        state = WindowState(current_count = 50, previous_count = 100)
        weighted = state.weighted_count(0.0)
        assert weighted == 150.0

    def test_weighted_count_end_of_window(self) -> None:
        state = WindowState(current_count = 50, previous_count = 100)
        weighted = state.weighted_count(1.0)
        assert weighted == 50.0

    def test_weighted_count_mid_window(self) -> None:
        state = WindowState(current_count = 50, previous_count = 100)
        weighted = state.weighted_count(0.5)
        assert weighted == 100.0

    def test_weighted_count_quarter_window(self) -> None:
        state = WindowState(current_count = 40, previous_count = 80)
        weighted = state.weighted_count(0.25)
        assert weighted == 80 * 0.75 + 40

    def test_factory_empty(self) -> None:
        state = WindowStateFactory.empty()
        assert state.current_count == 0
        assert state.previous_count == 0

    def test_factory_with_usage(self) -> None:
        state = WindowStateFactory.with_usage(current = 50, previous = 100)
        assert state.current_count == 50
        assert state.previous_count == 100


class TestTokenBucketState:
    """
    Tests for TokenBucketState
    """
    def test_create_state(self) -> None:
        state = TokenBucketState(
            tokens = 50.0,
            last_refill = 1000.0,
            capacity = 100,
            refill_rate = 1.67,
        )
        assert state.tokens == 50.0
        assert state.capacity == 100
        assert state.refill_rate == 1.67

    def test_factory_full(self) -> None:
        state = TokenBucketStateFactory.full(capacity = 200)
        assert state.tokens == 200.0
        assert state.capacity == 200

    def test_factory_empty(self) -> None:
        state = TokenBucketStateFactory.empty()
        assert state.tokens == 0.0


class TestCircuitState:
    """
    Tests for CircuitState
    """
    def test_default_closed(self) -> None:
        state = CircuitState()
        assert state.is_open is False
        assert state.failure_count == 0

    def test_factory_closed(self) -> None:
        state = CircuitStateFactory.closed()
        assert state.is_open is False

    def test_factory_open(self) -> None:
        state = CircuitStateFactory.open()
        assert state.is_open is True
        assert state.failure_count == 1
        assert state.last_failure_time > 0


class TestDefenseContext:
    """
    Tests for DefenseContext
    """
    def test_create_context(self) -> None:
        fp = FingerprintFactory.create()
        context = DefenseContext(
            fingerprint = fp,
            endpoint = TEST_ENDPOINT,
            method = "GET",
            is_authenticated = True,
            reputation_score = 0.9,
        )
        assert context.endpoint == TEST_ENDPOINT
        assert context.is_authenticated is True
        assert context.reputation_score == 0.9

    def test_factory_authenticated(self) -> None:
        context = DefenseContextFactory.authenticated()
        assert context.is_authenticated is True
        assert context.fingerprint.auth_identifier is not None

    def test_factory_suspicious(self) -> None:
        context = DefenseContextFactory.suspicious(reputation_score = 0.2)
        assert context.reputation_score == 0.2
        assert context.request_count_last_minute == 500


class TestRateLimitKey:
    """
    Tests for RateLimitKey and key building
    """
    def test_build_key(self) -> None:
        key = RateLimitKey(
            prefix = KEY_PREFIX,
            version = KEY_VERSION,
            layer = Layer.USER,
            endpoint = TEST_ENDPOINT,
            identifier = TEST_IP_V4,
            window = WINDOW_MINUTE,
        )
        built = key.build()
        expected = f"{KEY_PREFIX}:{KEY_VERSION}:user:{TEST_ENDPOINT}:{TEST_IP_V4}:{WINDOW_MINUTE}"
        assert built == expected

    def test_factory_user_key(self) -> None:
        key = KeyFactory.user_key()
        built = key.build()
        assert ":user:" in built
        assert TEST_ENDPOINT in built

    def test_factory_endpoint_key(self) -> None:
        key = KeyFactory.endpoint_key()
        built = key.build()
        assert ":endpoint:" in built
        assert ":global:" in built

    def test_factory_global_key(self) -> None:
        key = KeyFactory.global_key()
        built = key.build()
        assert ":global:" in built
