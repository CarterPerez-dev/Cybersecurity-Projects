"""
ⒸAngelaMos | 2025
__init__.py
"""
from __future__ import annotations

from typing import TYPE_CHECKING, TypeAlias

from fastapi_420.storage.memory import MemoryStorage
from fastapi_420.storage.redis_backend import RedisStorage
from fastapi_420.types import StorageType

if TYPE_CHECKING:
    from fastapi_420.config import StorageSettings


Storage: TypeAlias = MemoryStorage | RedisStorage  # noqa: UP040


def create_storage(settings: StorageSettings) -> Storage:
    """
    Factory function to create appropriate storage backend.
    """
    if settings.REDIS_URL is not None:
        return RedisStorage.from_settings(settings)
    return MemoryStorage.from_settings(settings)


__all__ = [
    "MemoryStorage",
    "RedisStorage",
    "Storage",
    "StorageType",
    "create_storage",
]
