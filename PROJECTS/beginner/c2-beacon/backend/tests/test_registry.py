"""
AngelaMos | 2026
test_registry.py

Unit tests for BeaconRegistry connection tracking and persistence

Verifies that registering a beacon adds it to both the in-memory
store and SQLite, that unregistering removes it from memory while
preserving the database record, and that query methods return correct
results.

Tests:
  beacon/registry.py - BeaconRegistry
"""

from pathlib import Path
from unittest.mock import AsyncMock

import aiosqlite
import pytest

from beacon.registry import BeaconRegistry
from core.models import BeaconMeta
from database import SCHEMA


@pytest.fixture
async def db(tmp_path: Path) -> aiosqlite.Connection:
    """
    Provide a fresh in-memory-like SQLite connection with schema
    """
    db_path = tmp_path / "test.db"
    conn = await aiosqlite.connect(db_path)
    conn.row_factory = aiosqlite.Row
    await conn.executescript(SCHEMA)
    await conn.commit()
    yield conn
    await conn.close()


@pytest.fixture
def registry() -> BeaconRegistry:
    """
    Provide a fresh BeaconRegistry instance
    """
    return BeaconRegistry()


@pytest.fixture
def sample_meta() -> BeaconMeta:
    """
    Provide sample beacon metadata
    """
    return BeaconMeta(
        hostname = "test-host",
        os = "Linux",
        username = "root",
        pid = 1234,
        internal_ip = "10.0.0.5",
        arch = "x86_64",
    )


class TestBeaconRegistry:
    """
    Verify beacon registration, unregistration, and queries
    """
    async def test_register_adds_to_active(
        self,
        registry: BeaconRegistry,
        sample_meta: BeaconMeta,
        db: aiosqlite.Connection,
    ) -> None:
        """
        Registering a beacon makes it appear in the active list
        """
        ws = AsyncMock()
        await registry.register("beacon-001", sample_meta, ws, db)

        assert registry.is_active("beacon-001")
        assert "beacon-001" in registry.list_active_ids()

    async def test_register_persists_to_db(
        self,
        registry: BeaconRegistry,
        sample_meta: BeaconMeta,
        db: aiosqlite.Connection,
    ) -> None:
        """
        Registering a beacon creates a database record
        """
        ws = AsyncMock()
        await registry.register("beacon-002", sample_meta, ws, db)

        record = await registry.get_one("beacon-002", db)
        assert record is not None
        assert record.hostname == "test-host"
        assert record.os == "Linux"

    async def test_unregister_removes_from_active(
        self,
        registry: BeaconRegistry,
        sample_meta: BeaconMeta,
        db: aiosqlite.Connection,
    ) -> None:
        """
        Unregistering a beacon removes it from the active list
        """
        ws = AsyncMock()
        await registry.register("beacon-003", sample_meta, ws, db)
        await registry.unregister("beacon-003", db)

        assert not registry.is_active("beacon-003")
        assert "beacon-003" not in registry.list_active_ids()

    async def test_unregister_preserves_db_record(
        self,
        registry: BeaconRegistry,
        sample_meta: BeaconMeta,
        db: aiosqlite.Connection,
    ) -> None:
        """
        Unregistering updates last_seen but does not delete the record
        """
        ws = AsyncMock()
        await registry.register("beacon-004", sample_meta, ws, db)
        await registry.unregister("beacon-004", db)

        record = await registry.get_one("beacon-004", db)
        assert record is not None

    async def test_get_all_returns_records(
        self,
        registry: BeaconRegistry,
        sample_meta: BeaconMeta,
        db: aiosqlite.Connection,
    ) -> None:
        """
        get_all returns all persisted beacon records
        """
        ws = AsyncMock()
        await registry.register("beacon-a", sample_meta, ws, db)
        await registry.register("beacon-b", sample_meta, ws, db)

        records = await registry.get_all(db)
        ids = {r.id for r in records}
        assert "beacon-a" in ids
        assert "beacon-b" in ids

    async def test_get_one_returns_none_for_missing(
        self,
        registry: BeaconRegistry,
        db: aiosqlite.Connection,
    ) -> None:
        """
        get_one returns None for a non-existent beacon ID
        """
        assert await registry.get_one("nonexistent", db) is None

    async def test_get_connection(
        self,
        registry: BeaconRegistry,
        sample_meta: BeaconMeta,
        db: aiosqlite.Connection,
    ) -> None:
        """
        get_connection returns the stored WebSocket
        """
        ws = AsyncMock()
        await registry.register("beacon-005", sample_meta, ws, db)

        assert registry.get_connection("beacon-005") is ws
        assert registry.get_connection("nonexistent") is None
