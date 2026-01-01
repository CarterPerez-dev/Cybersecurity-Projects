"""
ⒸAngelaMos | 2025
factory.py
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from config import settings, Environment, API_PREFIX
from core.database import sessionmanager
from core.exceptions import BaseAppException
from core.logging import configure_logging
from core.rate_limit import limiter
from middleware.correlation import CorrelationIdMiddleware
from core.common_schemas import AppInfoResponse
from core.health_routes import router as health_router
from user.routes import router as user_router
from auth.routes import router as auth_router
from admin.routes import router as admin_router


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """
    Application lifespan handler for startup and shutdown
    """
    configure_logging()
    sessionmanager.init(str(settings.DATABASE_URL))
    yield
    await sessionmanager.close()


OPENAPI_TAGS = [
    {
        "name": "root",
        "description": "API information"
    },
    {
        "name": "health",
        "description": "Health check endpoints"
    },
    {
        "name": "auth",
        "description": "Authentication and authorization"
    },
    {
        "name": "users",
        "description": "User registration and profile management"
    },
    {
        "name": "admin",
        "description": "Admin only operations"
    },
]


def create_app() -> FastAPI:
    """
    Application factory
    """
    is_production = settings.ENVIRONMENT == Environment.PRODUCTION

    app = FastAPI(
        title = settings.APP_NAME,
        summary = settings.APP_SUMMARY,
        description = settings.APP_DESCRIPTION,
        version = settings.APP_VERSION,
        contact = {
            "name": settings.APP_CONTACT_NAME,
            "email": settings.APP_CONTACT_EMAIL,
        },
        license_info = {
            "name": settings.APP_LICENSE_NAME,
            "url": settings.APP_LICENSE_URL,
        },
        openapi_tags = OPENAPI_TAGS,
        lifespan = lifespan,
        openapi_url = None if is_production else "/openapi.json",
        docs_url = None if is_production else "/docs",
        redoc_url = None if is_production else "/redoc",
    )

    app.add_middleware(CorrelationIdMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins = settings.CORS_ORIGINS,
        allow_credentials = settings.CORS_ALLOW_CREDENTIALS,
        allow_methods = settings.CORS_ALLOW_METHODS,
        allow_headers = settings.CORS_ALLOW_HEADERS,
    )

    app.state.limiter = limiter
    app.add_exception_handler(
        RateLimitExceeded,
        _rate_limit_exceeded_handler
    )

    @app.exception_handler(BaseAppException)
    async def app_exception_handler(
        request: Request,
        exc: BaseAppException,
    ) -> JSONResponse:
        return JSONResponse(
            status_code = exc.status_code,
            content = {
                "detail": exc.message,
                "type": exc.__class__.__name__,
            },
        )

    @app.get("/", response_model = AppInfoResponse, tags = ["root"])
    async def root() -> AppInfoResponse:
        return AppInfoResponse(
            name = settings.APP_NAME,
            version = settings.APP_VERSION,
            environment = settings.ENVIRONMENT.value,
            docs_url = None if is_production else "/docs",
        )

    app.include_router(health_router)
    app.include_router(admin_router, prefix = API_PREFIX)
    app.include_router(auth_router, prefix = API_PREFIX)
    app.include_router(user_router, prefix = API_PREFIX)

    return app
