"""
ⒸAngelaMos | 2025
Application entry point with uvicorn server command
"""

import uvicorn

from app.config import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    settings,
)


def main() -> None:
    """
    Run the FastAPI application with uvicorn
    """
    uvicorn.run(
        "app.factory:create_app",
        factory = True,
        host = DEFAULT_HOST,
        port = DEFAULT_PORT,
        reload = settings.is_development,
        log_level = "debug" if settings.DEBUG else "info",
        access_log = True,
    )


if __name__ == "__main__":
    main()
