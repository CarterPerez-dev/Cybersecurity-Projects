"""
©AngelaMos | 2026
test_integration.py
"""

import asyncio
import os
import shutil
import tempfile
from pathlib import Path

import pytest
from fakeredis.aioredis import FakeRedis
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel

from app.core.alerts.dispatcher import AlertDispatcher
from app.core.detection.rules import RuleEngine
from app.core.ingestion.pipeline import Pipeline
from app.core.ingestion.tailer import LogTailer
from app.models.threat_event import ThreatEvent

NORMAL_LINE = (
    "192.168.1.100 - - [11/Feb/2026:10:00:00 +0000] "
    '"GET /index.html HTTP/1.1" 200 4523 "-" '
    '"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
)

SQLI_LINE = (
    "198.51.100.10 - - [11/Feb/2026:10:00:01 +0000] "
    '"GET /search?q=1%27+OR+1=1-- HTTP/1.1" 200 5678 "-" '
    '"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
)

XSS_LINE = (
    "198.51.100.11 - - [11/Feb/2026:10:00:02 +0000] "
    '"GET /comment?text=<script>alert(1)</script> HTTP/1.1" 200 3210 "-" '
    '"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
)

PATH_TRAVERSAL_LINE = (
    "198.51.100.12 - - [11/Feb/2026:10:00:03 +0000] "
    '"GET /../../etc/passwd HTTP/1.1" 400 230 "-" '
    '"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
)


def _write_lines(log_path: str, *lines: str) -> None:
    """
    Append lines to the log file and force an OS-level flush
    so inotify fires immediately.
    """
    with open(log_path, "a") as f:
        for line in lines:
            f.write(line + "\n")
        f.flush()
        os.fsync(f.fileno())


@pytest.fixture
async def integration_env():
    """
    Full-stack integration environment with in-memory DB,
    fake Redis, pipeline, and temp log directory.
    """

    tmp_dir = tempfile.mkdtemp()
    log_path = os.path.join(tmp_dir, "access.log")
    Path(log_path).touch()

    fake_redis = FakeRedis(decode_responses=True)
    engine = create_async_engine(
        "sqlite+aiosqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

    session_factory = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    dispatcher = AlertDispatcher(fake_redis, session_factory)
    rule_engine = RuleEngine()

    pipeline = Pipeline(
        redis_client=fake_redis,
        rule_engine=rule_engine,
        on_result=dispatcher.dispatch,
    )
    await pipeline.start()

    loop = asyncio.get_running_loop()
    tailer = LogTailer(log_path, pipeline.raw_queue, loop)
    tailer.start()

    await asyncio.sleep(0.5)

    yield {
        "log_path": log_path,
        "pipeline": pipeline,
        "tailer": tailer,
        "session_factory": session_factory,
        "engine": engine,
    }

    tailer.stop()
    await pipeline.stop()
    await engine.dispose()
    shutil.rmtree(tmp_dir, ignore_errors=True)


async def _poll_threat_count(
    session_factory: async_sessionmaker[AsyncSession],
    expected: int,
    timeout: float = 8.0,
) -> int:
    """
    Poll the database until the expected threat count is reached or timeout.
    """
    count = 0
    for _ in range(int(timeout / 0.1)):
        await asyncio.sleep(0.1)
        async with session_factory() as session:
            result = await session.execute(select(func.count()).select_from(ThreatEvent))
            count = result.scalar_one()
            if count >= expected:
                return count
    return count


@pytest.mark.asyncio
async def test_tailer_to_db_end_to_end(integration_env) -> None:
    """
    Write log lines to a file - tailer picks them up - pipeline processes -
    dispatcher stores MEDIUM+ threats in the database.
    """
    env = integration_env
    _write_lines(
        env["log_path"],
        NORMAL_LINE,
        SQLI_LINE,
        XSS_LINE,
        PATH_TRAVERSAL_LINE,
    )

    count = await _poll_threat_count(env["session_factory"], expected=3)
    assert count >= 3, f"Expected >= 3 stored threats, got {count}"


@pytest.mark.asyncio
async def test_only_medium_plus_stored(integration_env) -> None:
    """
    Normal (LOW severity) requests are NOT stored in the database.
    Only MEDIUM and HIGH severity threats are persisted.
    """
    env = integration_env
    lines = [
        f"192.168.1.{i + 1} - - [11/Feb/2026:10:00:0{i} +0000] "
        f'"GET /page/{i} HTTP/1.1" 200 1234 "-" '
        f'"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
        for i in range(5)
    ]
    _write_lines(env["log_path"], *lines)

    await asyncio.sleep(2.0)

    async with env["session_factory"]() as session:
        result = await session.execute(select(func.count()).select_from(ThreatEvent))
        count = result.scalar_one()

    assert count == 0


@pytest.mark.asyncio
async def test_stored_threats_have_correct_fields(integration_env) -> None:
    """
    Stored threat events have populated severity, score, and matched rules.
    """
    env = integration_env
    _write_lines(env["log_path"], SQLI_LINE)

    count = await _poll_threat_count(env["session_factory"], expected=1)
    assert count >= 1, f"Expected >= 1 stored threat, got {count}"

    async with env["session_factory"]() as session:
        rows = (await session.execute(select(ThreatEvent))).scalars().all()

    event = rows[0]
    assert event.severity in ("HIGH", "MEDIUM")
    assert event.threat_score >= 0.5
    assert len(event.matched_rules) > 0
    assert len(event.feature_vector) == 35
    assert event.source_ip == "198.51.100.10"
