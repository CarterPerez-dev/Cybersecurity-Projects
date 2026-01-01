"""
ⒸAngelaMos | 2025
__main__.py
"""
import uvicorn

from config import settings
from factory import create_app


app = create_app()

if __name__ == "__main__":
    uvicorn.run(
        "__main__:app",
        host = settings.HOST,
        port = settings.PORT,
        reload = settings.RELOAD,
    )
