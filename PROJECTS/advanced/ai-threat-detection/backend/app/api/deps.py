"""
©AngelaMos | 2026
deps.py
"""

from collections.abc import AsyncIterator

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    """
    Yield an async database session from
    the application's session factory
    """
    factory = request.app.state.session_factory
    async with factory() as session:
        yield session
        await session.commit()
