"""
ⒸAngelaMos | 2025
FastAPI application factory for main.py
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from slowapi import (
    Limiter,
    _rate_limit_exceeded_handler,
)
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from config import settings
from core.database import Base, engine
from routes import auth_router, scans_router


def create_app() -> FastAPI:
    """
    Application factory function
    """
    Base.metadata.create_all(bind = engine)

    app = FastAPI(
        title = settings.APP_NAME,
        version = settings.VERSION,
        openapi_version = "3.1.0",
        docs_url = "/docs",
        redoc_url = "/redoc",
        openapi_url = "/openapi.json",
        debug = settings.DEBUG,
    )

    limiter = Limiter(key_func = get_remote_address)
    app.state.limiter = limiter
    app.add_exception_handler(
        RateLimitExceeded,
        _rate_limit_exceeded_handler
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins = settings.cors_origins_list,
        allow_credentials = True,
        allow_methods = ["*"],
        allow_headers = ["*"],
    )

    _register_routes(app)

    return app


def _register_routes(app: FastAPI) -> None:
    """
    Register all application routes
    """
    @app.get("/")
    def root() -> dict[str, str]:
        """
        API root endpoint
        """
        return {
            "app": settings.APP_NAME,
            "version": settings.VERSION,
            "status": "healthy",
        }

    @app.get("/health")
    def health_check() -> dict[str, str]:
        """
        Health check endpoint
        """
        return {"status": "healthy"}

    app.include_router(auth_router)
    app.include_router(scans_router)
