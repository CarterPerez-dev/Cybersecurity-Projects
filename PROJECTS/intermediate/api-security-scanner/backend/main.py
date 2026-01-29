"""
ⒸCertGames.com | 2025
ⒸAngelaMos | CarterPerez-dev
----
API Security Scanner FastAPI entry point
"""

import uvicorn

from config import settings
from factory import create_app


app = create_app()

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host = settings.BACKEND_HOST,
        port = settings.BACKEND_PORT,
        reload = settings.DEBUG,
    )
