"""
©AngelaMos | 2026
__main__.py
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
