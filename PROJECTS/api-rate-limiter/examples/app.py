"""
ⒸAngelaMos | 2025
app.py
"""

from __future__ import annotations

import uvicorn
from typing import Annotated
from contextlib import asynccontextmanager

from fastapi import (
    Depends,
    FastAPI,
    Request,
)
from fastapi_420 import (
    RateLimiter,
    RateLimiterSettings,
    RateLimitMiddleware,
    ScopedRateLimiter,
    FingerprintSettings,
    StorageSettings,
    set_global_limiter,
    RateLimitDep,
)
from fastapi_420.types import Algorithm, FingerprintLevel


storage_settings = StorageSettings(
    REDIS_URL = "redis://localhost:6767/0",
    MEMORY_MAX_KEYS = 50_000,
)

fingerprint_settings = FingerprintSettings(
    LEVEL = FingerprintLevel.NORMAL,
    TRUST_X_FORWARDED_FOR = True,
)

settings = RateLimiterSettings(
    ALGORITHM = Algorithm.SLIDING_WINDOW,
    KEY_PREFIX = "myapp",
    INCLUDE_HEADERS = True,
    FAIL_OPEN = True,
    LOG_VIOLATIONS = True,
    storage = storage_settings,
    fingerprint = fingerprint_settings,
)

limiter = RateLimiter(settings = settings)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await limiter.init()
    set_global_limiter(limiter)
    yield
    await limiter.close()


app = FastAPI(
    title = "Rate Limited API",
    description = "Example API demonstrating fastapi_420 rate limiting",
    lifespan = lifespan,
)

auth_limiter = ScopedRateLimiter(
    prefix = "/auth",
    default_rules = ["5/minute",
                     "20/hour"],
    endpoint_rules = {
        "POST:/auth/login": ["3/minute",
                             "10/hour"],
        "POST:/auth/register": ["2/minute",
                                "5/hour"],
        "POST:/auth/forgot-password": ["2/minute",
                                       "5/hour"],
    },
)

public_limiter = ScopedRateLimiter(
    prefix = "/public",
    default_rules = ["100/minute",
                     "1000/hour"],
)

user_limiter = ScopedRateLimiter(
    prefix = "/api",
    default_rules = ["60/minute",
                     "500/hour"],
    endpoint_rules = {
        "POST:/api/upload": ["10/minute"],
        "GET:/api/export": ["5/minute"],
    },
)


@app.post("/auth/login", dependencies = [Depends(auth_limiter)])
async def login(username: str, password: str):
    """
    Strict rate limit: 3/minute, 10/hour
    Prevents brute force attacks
    """
    return {"token": "fake_jwt_token", "user": username}


@app.post("/auth/register", dependencies = [Depends(auth_limiter)])
async def register(username: str, email: str, password: str):
    """
    Very strict: 2/minute, 5/hour
    Prevents mass account creation
    """
    return {"user_id": 123, "username": username}


@app.post("/auth/forgot-password", dependencies = [Depends(auth_limiter)])
async def forgot_password(email: str):
    """
    Very strict: 2/minute, 5/hour
    Prevents email bombing
    """
    return {"message": "If that email exists, we sent a reset link"}


@app.get("/public/products")
@limiter.limit("100/minute")
async def list_products(request: Request):
    """
    Relaxed limit for public browsing
    Uses decorator style
    """
    return {"products": [{"id": 1, "name": "Widget"}]}


@app.get("/public/search")
@limiter.limit("50/minute")
async def search(request: Request, q: str):
    """
    Slightly stricter for search (more expensive)
    """
    return {"results": [], "query": q}


@app.get("/api/me", dependencies = [Depends(user_limiter)])
async def get_current_user():
    """
    Standard user endpoint: 60/minute
    """
    return {"user_id": 123, "username": "johndoe"}


@app.get(
    "/api/dashboard",
    dependencies = [Depends(user_limiter)],
)
async def dashboard():
    """
    Standard user endpoint: 60/minute
    """
    return {"stats": {"visits": 1000, "conversions": 50}}


@app.post("/api/upload", dependencies = [Depends(user_limiter)])
async def upload_file():
    """
    Stricter for uploads: 10/minute
    """
    return {"file_id": "abc123", "status": "uploaded"}


@app.get("/api/export", dependencies = [Depends(user_limiter)])
async def export_data():
    """
    Very strict for exports: 5/minute
    Expensive operation
    """
    return {"download_url": "/files/export_123.csv"}


@app.get(
    "/api/settings",
    dependencies = [Depends(RateLimitDep("30/minute"))],
)
async def get_settings():
    """
    Using RateLimitDep directly for one off limits
    """
    return {"theme": "dark", "notifications": True}


@app.get("/admin/users")
async def admin_list_users():
    """
    No rate limit for admin endpoints
    In production you would add auth middleware
    """
    return {"users": [{"id": 1, "username": "admin"}]}


@app.get("/admin/stats")
async def admin_stats():
    """
    No rate limit
    """
    return {"total_users": 10000, "active_today": 500}


@app.get("/health")
async def health():
    """
    Health check, excluded from rate limiting by default
    """
    storage_healthy = await limiter._storage.health_check(
    ) if limiter._storage else False
    return {
        "status": "healthy",
        "limiter_initialized": limiter.is_initialized,
        "storage_healthy": storage_healthy,
    }


if __name__ == "__main__":
    uvicorn.run(app, host = "0.0.0.0", port = 8000)
