"""
AngelaMos | 2026
database.py

SQLite schema definition and async connection management

Holds the three-table schema (beacons, tasks, task_results) as a SQL
string and exposes init_db for first-run setup and get_db as an async
context manager. WAL mode and foreign keys are enabled on every
connection.

Connects to:
  config.py - reads DATABASE_PATH via settings
  beacon/router.py - calls get_db()
  ops/router.py - calls get_db()
  __main__.py - calls init_db()
  tests/test_registry.py - imports SCHEMA
  tests/test_tasking.py - imports SCHEMA
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import aiosqlite

from app.config import settings


SCHEMA = """
CREATE TABLE IF NOT EXISTS beacons (
    id          TEXT PRIMARY KEY,
    hostname    TEXT NOT NULL,
    os          TEXT NOT NULL,
    username    TEXT NOT NULL,
    pid         INTEGER NOT NULL,
    internal_ip TEXT NOT NULL,
    arch        TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tasks (
    id           TEXT PRIMARY KEY,
    beacon_id    TEXT NOT NULL,
    command      TEXT NOT NULL,
    args         TEXT,
    status       TEXT NOT NULL DEFAULT 'pending',
    created_at   TEXT NOT NULL,
    completed_at TEXT,
    FOREIGN KEY (beacon_id) REFERENCES beacons(id)
);

CREATE TABLE IF NOT EXISTS task_results (
    id         TEXT PRIMARY KEY,
    task_id    TEXT NOT NULL UNIQUE,
    output     TEXT,
    error      TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (task_id) REFERENCES tasks(id)
);
"""


async def init_db() -> None:
    """
    Create database directory and initialize schema
    """
    settings.DATABASE_PATH.parent.mkdir(parents = True, exist_ok = True)
    async with aiosqlite.connect(settings.DATABASE_PATH) as db:
        await db.executescript(SCHEMA)
        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute("PRAGMA foreign_keys=ON")
        await db.commit()


@asynccontextmanager
async def get_db() -> AsyncIterator[aiosqlite.Connection]:
    """
    Async context manager yielding a database connection
    """
    db = await aiosqlite.connect(settings.DATABASE_PATH)
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA foreign_keys=ON")
    try:
        yield db
    finally:
        await db.close()
