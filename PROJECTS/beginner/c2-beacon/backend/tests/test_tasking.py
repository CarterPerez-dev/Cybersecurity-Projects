"""
AngelaMos | 2026
test_tasking.py

Unit tests for TaskManager queue behavior and SQLite persistence

Verifies task submission, FIFO ordering, blocking get_next behavior,
result storage and status transitions, task history queries, and queue
cleanup on beacon disconnect.

Tests:
  beacon/tasking.py - TaskManager
"""

import asyncio
from pathlib import Path

import aiosqlite
import pytest

from beacon.tasking import TaskManager
from core.models import CommandType, TaskRecord, TaskResult
from database import SCHEMA


@pytest.fixture
async def db(tmp_path: Path) -> aiosqlite.Connection:
    """
    Provide a fresh SQLite connection with schema
    """
    db_path = tmp_path / "test.db"
    conn = await aiosqlite.connect(db_path)
    conn.row_factory = aiosqlite.Row
    await conn.executescript(SCHEMA)
    await conn.execute(
        """
        INSERT INTO beacons (id, hostname, os, username, pid, internal_ip, arch, first_seen, last_seen)
        VALUES ('beacon-t', 'test', 'Linux', 'root', 1, '10.0.0.1', 'x86_64', '2026-01-01', '2026-01-01')
        """
    )
    await conn.commit()
    yield conn
    await conn.close()


@pytest.fixture
def task_manager() -> TaskManager:
    """
    Provide a fresh TaskManager instance
    """
    return TaskManager()


def _make_task(task_id: str, beacon_id: str = "beacon-t") -> TaskRecord:
    """
    Create a sample TaskRecord
    """
    return TaskRecord(
        id = task_id,
        beacon_id = beacon_id,
        command = CommandType.SHELL,
        args = "whoami",
    )


class TestTaskManager:
    """
    Verify task submission, retrieval, and result storage
    """
    async def test_submit_and_get_next(
        self,
        task_manager: TaskManager,
        db: aiosqlite.Connection,
    ) -> None:
        """
        Submitted task can be retrieved from the queue
        """
        task = _make_task("task-001")
        await task_manager.submit(task, db)

        retrieved = await asyncio.wait_for(
            task_manager.get_next("beacon-t"),
            timeout = 1.0
        )
        assert retrieved.id == "task-001"
        assert retrieved.command == CommandType.SHELL

    async def test_submit_persists_to_db(
        self,
        task_manager: TaskManager,
        db: aiosqlite.Connection,
    ) -> None:
        """
        Submitted task is persisted in SQLite
        """
        task = _make_task("task-002")
        await task_manager.submit(task, db)

        cursor = await db.execute("SELECT * FROM tasks WHERE id = ?",
                                  ("task-002",
                                   ))
        row = await cursor.fetchone()
        assert row is not None
        assert dict(row)["command"] == "shell"

    async def test_tasks_queue_in_order(
        self,
        task_manager: TaskManager,
        db: aiosqlite.Connection,
    ) -> None:
        """
        Tasks are dequeued in FIFO order
        """
        await task_manager.submit(_make_task("first"), db)
        await task_manager.submit(_make_task("second"), db)
        await task_manager.submit(_make_task("third"), db)

        t1 = await asyncio.wait_for(task_manager.get_next("beacon-t"), timeout = 1.0)
        t2 = await asyncio.wait_for(task_manager.get_next("beacon-t"), timeout = 1.0)
        t3 = await asyncio.wait_for(task_manager.get_next("beacon-t"), timeout = 1.0)

        assert [t1.id, t2.id, t3.id] == ["first", "second", "third"]

    async def test_store_result(
        self,
        task_manager: TaskManager,
        db: aiosqlite.Connection,
    ) -> None:
        """
        Storing a result updates the task status to completed
        """
        task = _make_task("task-003")
        await task_manager.submit(task, db)

        result = TaskResult(
            id = "result-001",
            task_id = "task-003",
            output = "root\n",
        )
        await task_manager.store_result(result, db)

        cursor = await db.execute(
            "SELECT status FROM tasks WHERE id = ?",
            ("task-003",
             )
        )
        row = await cursor.fetchone()
        assert dict(row)["status"] == "completed"

    async def test_get_history(
        self,
        task_manager: TaskManager,
        db: aiosqlite.Connection,
    ) -> None:
        """
        Task history includes task details joined with results
        """
        task = _make_task("task-004")
        await task_manager.submit(task, db)

        result = TaskResult(
            id = "result-002",
            task_id = "task-004",
            output = "test output",
        )
        await task_manager.store_result(result, db)

        history = await task_manager.get_history("beacon-t", db)
        assert len(history) >= 1
        entry = history[0]
        assert entry["command"] == "shell"
        assert entry["output"] == "test output"

    async def test_get_next_blocks_until_task(
        self,
        task_manager: TaskManager,
        db: aiosqlite.Connection,
    ) -> None:
        """
        get_next blocks when the queue is empty and resolves when a task arrives
        """
        async def delayed_submit() -> None:
            await asyncio.sleep(0.1)
            await task_manager.submit(_make_task("delayed"), db)

        background_task = asyncio.create_task(delayed_submit())
        retrieved = await asyncio.wait_for(
            task_manager.get_next("beacon-t"),
            timeout = 2.0
        )
        assert retrieved.id == "delayed"
        await background_task

    def test_remove_queue(self, task_manager: TaskManager) -> None:
        """
        remove_queue cleans up the beacon queue
        """
        task_manager._ensure_queue("beacon-x")
        assert "beacon-x" in task_manager._queues
        task_manager.remove_queue("beacon-x")
        assert "beacon-x" not in task_manager._queues
