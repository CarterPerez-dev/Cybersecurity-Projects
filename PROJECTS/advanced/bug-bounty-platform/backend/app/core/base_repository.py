"""
ⒸAngelaMos | 2025
base_repository.py
"""

from collections.abc import Sequence
from typing import (
    Any,
    Generic,
    TypeVar,
)
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .Base import Base


ModelT = TypeVar("ModelT", bound = Base)


class BaseRepository(Generic[ModelT]):
    """
    Generic repository with common CRUD operations
    """
    model: type[ModelT]

    @classmethod
    async def get_by_id(
        cls,
        session: AsyncSession,
        id: UUID,
    ) -> ModelT | None:
        """
        Get a single record by ID
        """
        return await session.get(cls.model, id)

    @classmethod
    async def get_multi(
        cls,
        session: AsyncSession,
        skip: int = 0,
        limit: int = 100,
    ) -> Sequence[ModelT]:
        """
        Get multiple records with pagination
        """
        result = await session.execute(
            select(cls.model).offset(skip).limit(limit)
        )
        return result.scalars().all()

    @classmethod
    async def count(cls, session: AsyncSession) -> int:
        """
        Count total records
        """
        result = await session.execute(
            select(func.count()).select_from(cls.model)
        )
        return result.scalar_one()

    @classmethod
    async def create(
        cls,
        session: AsyncSession,
        **kwargs: Any,
    ) -> ModelT:
        """
        Create a new record
        """
        instance = cls.model(**kwargs)
        session.add(instance)
        await session.flush()
        await session.refresh(instance)
        return instance

    @classmethod
    async def update(
        cls,
        session: AsyncSession,
        instance: ModelT,
        **kwargs: Any,
    ) -> ModelT:
        """
        Update an existing record
        """
        for key, value in kwargs.items():
            setattr(instance, key, value)
        await session.flush()
        await session.refresh(instance)
        return instance

    @classmethod
    async def delete(
        cls,
        session: AsyncSession,
        instance: ModelT,
    ) -> None:
        """
        Delete a record
        """
        await session.delete(instance)
        await session.flush()
