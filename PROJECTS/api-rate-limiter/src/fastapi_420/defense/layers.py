"""
ⒸAngelaMos | 2025
layers.py
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from fastapi_420.algorithms import create_algorithm
from fastapi_420.exceptions import EnhanceYourCalm
from fastapi_420.types import (
    DefenseContext,
    DefenseMode,
    FingerprintData,
    Layer,
    RateLimitKey,
    RateLimitResult,
    RateLimitRule,
)

if TYPE_CHECKING:
    from starlette.requests import Request

    from fastapi_420.config import RateLimiterSettings
    from fastapi_420.defense.circuit_breaker import CircuitBreaker
    from fastapi_420.storage import Storage


logger = logging.getLogger("fastapi_420")


@dataclass
class LayerResult:
    """
    Result from a defense layer check
    """
    layer: Layer
    allowed: bool
    result: RateLimitResult
    should_continue: bool = True


class LayeredDefense:
    """
    Three-layer defense system for comprehensive rate limiting

    Layer 1: Per-User Per-Endpoint (granular)
    Layer 2: Per-Endpoint Global (endpoint protection)
    Layer 3: Global Circuit Breaker (DDoS protection)
    """
    def __init__(
        self,
        storage: Storage,
        settings: RateLimiterSettings,
        circuit_breaker: CircuitBreaker | None = None,
    ) -> None:
        self._storage = storage
        self._settings = settings
        self._circuit_breaker = circuit_breaker
        self._algorithm = create_algorithm(settings.ALGORITHM)

    async def check_all_layers(
        self,
        request: Request,
        fingerprint: FingerprintData,
        endpoint: str,
        rules: list[RateLimitRule],
    ) -> RateLimitResult:
        """
        Check all defense layers in order
        """
        context = DefenseContext(
            fingerprint = fingerprint,
            endpoint = endpoint,
            method = request.method,
            is_authenticated = fingerprint.auth_identifier is not None,
        )

        layer3_result = await self._check_layer3_global(context)
        if not layer3_result.allowed:
            self._log_violation(layer3_result, context)
            raise EnhanceYourCalm(
                result = layer3_result.result,
                message = self._settings.HTTP_420_MESSAGE,
                detail = "API is under heavy load. Please try again later.",
            )

        layer2_result = await self._check_layer2_endpoint(context, rules)
        if not layer2_result.allowed:
            self._log_violation(layer2_result, context)
            raise EnhanceYourCalm(
                result = layer2_result.result,
                message = self._settings.HTTP_420_MESSAGE,
                detail = self._settings.HTTP_420_DETAIL,
            )

        layer1_result = await self._check_layer1_user(context, rules)
        if not layer1_result.allowed:
            self._log_violation(layer1_result, context)
            raise EnhanceYourCalm(
                result = layer1_result.result,
                message = self._settings.HTTP_420_MESSAGE,
                detail = self._settings.HTTP_420_DETAIL,
            )

        return layer1_result.result

    async def _check_layer1_user(
        self,
        context: DefenseContext,
        rules: list[RateLimitRule],
    ) -> LayerResult:
        """
        Layer 1: Per-user per-endpoint rate limiting
        """
        identifier = context.fingerprint.to_composite_key(
            self._settings.fingerprint.LEVEL
        )

        worst_result: RateLimitResult | None = None

        for rule in rules:
            key = RateLimitKey(
                prefix = self._settings.KEY_PREFIX,
                version = self._settings.KEY_VERSION,
                layer = Layer.USER,
                endpoint = context.endpoint,
                identifier = identifier,
                window = rule.window_seconds,
            ).build()

            result = await self._algorithm.check(
                storage = self._storage,
                key = key,
                rule = rule,
            )

            if not result.allowed:  # noqa: SIM102
                if worst_result is None or (result.retry_after or 0) > (
                        worst_result.retry_after or 0):
                    worst_result = result

        if worst_result:
            return LayerResult(
                layer = Layer.USER,
                allowed = False,
                result = worst_result,
            )

        return LayerResult(
            layer = Layer.USER,
            allowed = True,
            result = result,
        )

    async def _check_layer2_endpoint(
        self,
        context: DefenseContext,
        rules: list[RateLimitRule],  # noqa: ARG002
    ) -> LayerResult:
        """
        Layer 2: Per-endpoint global rate limiting
        """
        endpoint_rules = self._settings.endpoint_limits.get(
            context.endpoint,
            self._settings.get_default_rules()
        )

        for rule in endpoint_rules:
            key = RateLimitKey(
                prefix = self._settings.KEY_PREFIX,
                version = self._settings.KEY_VERSION,
                layer = Layer.ENDPOINT,
                endpoint = context.endpoint,
                identifier = "global",
                window = rule.window_seconds,
            ).build()

            endpoint_rule = RateLimitRule(
                requests = rule.requests *
                self._settings.defense.ENDPOINT_LIMIT_MULTIPLIER,
                window_seconds = rule.window_seconds,
            )

            result = await self._algorithm.check(
                storage = self._storage,
                key = key,
                rule = endpoint_rule,
            )

            if not result.allowed:
                return LayerResult(
                    layer = Layer.ENDPOINT,
                    allowed = False,
                    result = result,
                )

        return LayerResult(
            layer = Layer.ENDPOINT,
            allowed = True,
            result = result,
        )

    async def _check_layer3_global(
        self,
        context: DefenseContext,
    ) -> LayerResult:
        """
        Layer 3: Global circuit breaker
        """
        if self._circuit_breaker is None:
            return LayerResult(
                layer = Layer.GLOBAL,
                allowed = True,
                result = RateLimitResult(
                    allowed = True,
                    limit = 0,
                    remaining = 0,
                    reset_after = 0,
                ),
            )

        is_allowed = await self._circuit_breaker.check(self._storage)

        if not is_allowed:
            if self._should_bypass_circuit(context):
                return LayerResult(
                    layer = Layer.GLOBAL,
                    allowed = True,
                    result = RateLimitResult(
                        allowed = True,
                        limit = 0,
                        remaining = 0,
                        reset_after = 0,
                    ),
                )

            return LayerResult(
                layer = Layer.GLOBAL,
                allowed = False,
                result = RateLimitResult(
                    allowed = False,
                    limit = self._circuit_breaker.threshold,
                    remaining = 0,
                    reset_after = float(
                        self._circuit_breaker.recovery_time
                    ),
                    retry_after = float(
                        self._circuit_breaker.recovery_time
                    ),
                ),
            )

        await self._circuit_breaker.record_request(self._storage)

        return LayerResult(
            layer = Layer.GLOBAL,
            allowed = True,
            result = RateLimitResult(
                allowed = True,
                limit = self._circuit_breaker.threshold,
                remaining = max(
                    0,
                    self._circuit_breaker.threshold - self._circuit_breaker
                    .current_state.total_requests_in_window,
                ),
                reset_after = float(self._circuit_breaker.window_seconds),
            ),
        )

    def _should_bypass_circuit(self, context: DefenseContext) -> bool:
        """
        Determine if request should bypass open circuit
        """
        mode = self._settings.defense.MODE

        if mode == DefenseMode.DISABLED:
            return True

        if mode == DefenseMode.LOCKDOWN:
            if self._settings.defense.LOCKDOWN_ALLOW_AUTHENTICATED and context.is_authenticated:
                return True

            return self._settings.defense.LOCKDOWN_ALLOW_KNOWN_GOOD and context.reputation_score >= 0.9

        if mode == DefenseMode.ADAPTIVE:
            return bool(context.is_authenticated)

        return False

    def _log_violation(
        self,
        layer_result: LayerResult,
        context: DefenseContext,
    ) -> None:
        """
        Log rate limit violation
        """
        if not self._settings.LOG_VIOLATIONS:
            return

        logger.warning(
            "Rate limit exceeded",
            extra = {
                "layer": layer_result.layer.value,
                "endpoint": context.endpoint,
                "method": context.method,
                "is_authenticated": context.is_authenticated,
                "remaining": layer_result.result.remaining,
                "reset_after": layer_result.result.reset_after,
            },
        )
