"""
©AngelaMos | 2026
__main__.py

Uvicorn entry point for the AngelusVigil API server

Launches app.main:app via uvicorn using host, port, and
reload settings from app.config.settings

Connects to:
  config.py - settings.host, settings.port, settings.debug
  main.py   - ASGI application instance
"""

import uvicorn

from app.config import settings


def main() -> None:
    """
    Run the AngelusVigil API server
    """
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
    )


if __name__ == "__main__":
    main()
