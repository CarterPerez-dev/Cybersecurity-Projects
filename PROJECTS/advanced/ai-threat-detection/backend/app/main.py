"""
©AngelaMos | 2026
main.py

ASGI application instance created by the factory

Connects to:
  factory.py - create_app builds the FastAPI instance
"""

from app.factory import create_app

app = create_app()
