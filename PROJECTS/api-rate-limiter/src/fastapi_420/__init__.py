"""
ⒸAngelaMos | 2025
__init__.py
"""

from fastapi_420.config import (
    FingerprintSettings,
    RateLimiterSettings,
    StorageSettings,
    get_settings,
)
from fastapi_420.defense import CircuitBreaker, LayeredDefense
from fastapi_420.dependencies import (
    LimiterDep,
    RateLimitDep,
    ScopedRateLimiter,
    create_rate_limit_dep,
    get_limiter,
    require_rate_limit,
    set_global_limiter,
)
from fastapi_420.exceptions import (
    EnhanceYourCalm,
    HTTP_420_ENHANCE_YOUR_CALM,
    RateLimitError,
    RateLimitExceeded,
    StorageError,
)
from fastapi_420.limiter import RateLimiter
from fastapi_420.middleware import RateLimitMiddleware, SlowDownMiddleware
from fastapi_420.types import (
    Algorithm,
    DefenseMode,
    FingerprintData,
    FingerprintLevel,
    Layer,
    RateLimitResult,
    RateLimitRule,
)


__version__ = "0.1.0"

__all__ = [
    "HTTP_420_ENHANCE_YOUR_CALM",
    "Algorithm",
    "CircuitBreaker",
    "DefenseMode",
    "EnhanceYourCalm",
    "FingerprintData",
    "FingerprintLevel",
    "FingerprintSettings",
    "Layer",
    "LayeredDefense",
    "LimiterDep",
    "RateLimitDep",
    "RateLimitError",
    "RateLimitExceeded",
    "RateLimitMiddleware",
    "RateLimitResult",
    "RateLimitRule",
    "RateLimiter",
    "RateLimiterSettings",
    "ScopedRateLimiter",
    "SlowDownMiddleware",
    "StorageError",
    "StorageSettings",
    "__version__",
    "create_rate_limit_dep",
    "get_limiter",
    "get_settings",
    "require_rate_limit",
    "set_global_limiter",
]
