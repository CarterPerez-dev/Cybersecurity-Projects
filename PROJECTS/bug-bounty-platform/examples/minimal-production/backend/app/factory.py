"""
ⒸAngelaMos | 2025
factory.py
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from config import settings, Environment, API_PREFIX
from core.database import sessionmanager
from core.exceptions import BaseAppException
from core.common_schemas import AppInfoResponse
from core.health_routes import router as health_router
from user.routes import router as user_router
from auth.routes import router as auth_router


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """
    Application lifespan handler for startup and shutdown
    """
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
        "description": "Authentication"
    },
    {
        "name": "users",
        "description": "User operations"
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
        openapi_tags = OPENAPI_TAGS,
        lifespan = lifespan,
        openapi_url = None if is_production else "/openapi.json",
        docs_url = None if is_production else "/docs",
        redoc_url = None if is_production else "/redoc",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins = settings.CORS_ORIGINS,
        allow_credentials = settings.CORS_ALLOW_CREDENTIALS,
        allow_methods = settings.CORS_ALLOW_METHODS,
        allow_headers = settings.CORS_ALLOW_HEADERS,
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
    app.include_router(auth_router, prefix = API_PREFIX)
    app.include_router(user_router, prefix = API_PREFIX)

    return app
