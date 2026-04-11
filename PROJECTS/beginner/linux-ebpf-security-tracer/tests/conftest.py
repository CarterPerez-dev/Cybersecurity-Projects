"""
©AngelaMos | 2026
conftest.py
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from src.processor import TracerEvent


@pytest.fixture()
def make_event():
    """
    Factory for creating TracerEvent instances in tests
    """

    def _make(
        event_type: str = "execve",
        category: str = "process",
        pid: int = 1000,
        ppid: int = 999,
        uid: int = 1000,
        gid: int = 1000,
        comm: str = "test",
        filename: str = "",
        addr_v4: str = "",
        port: int = 0,
        protocol: int = 0,
        target_uid: int = 0,
        target_gid: int = 0,
        ptrace_request: int = 0,
        target_pid: int = 0,
        flags: int = 0,
        severity: str = "LOW",
    ) -> TracerEvent:
        return TracerEvent(
            timestamp=datetime.now(tz=timezone.utc),
            event_type=event_type,
            category=category,
            pid=pid,
            ppid=ppid,
            uid=uid,
            gid=gid,
            username="testuser",
            comm=comm,
            filename=filename,
            addr_v4=addr_v4,
            port=port,
            protocol=protocol,
            target_uid=target_uid,
            target_gid=target_gid,
            ptrace_request=ptrace_request,
            target_pid=target_pid,
            flags=flags,
            severity=severity,
        )

    return _make
