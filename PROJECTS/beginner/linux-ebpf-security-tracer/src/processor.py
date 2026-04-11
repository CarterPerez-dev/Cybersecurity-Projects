"""
©AngelaMos | 2026
processor.py
"""
from __future__ import annotations

import ctypes
import pwd
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import (
    EVENT_TYPE_CATEGORIES,
    EVENT_TYPE_NAMES,
    MAX_FILENAME_LEN,
    SEVERITY_ORDER,
    TASK_COMM_LEN,
    Severity,
    TracerType,
)


class RawEvent(ctypes.Structure):
    """
    Mirrors the C struct event layout from eBPF programs
    """
    _fields_ = [
        ("timestamp_ns", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("ppid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("gid", ctypes.c_uint32),
        ("event_type", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("comm", ctypes.c_char * TASK_COMM_LEN),
        ("filename", ctypes.c_char * MAX_FILENAME_LEN),
        ("addr_v4", ctypes.c_uint32),
        ("port", ctypes.c_uint16),
        ("protocol", ctypes.c_uint16),
        ("target_uid", ctypes.c_uint32),
        ("target_gid", ctypes.c_uint32),
        ("ptrace_request", ctypes.c_uint32),
        ("target_pid", ctypes.c_uint32),
    ]


@dataclass
class TracerEvent:
    """
    Processed event with enriched metadata
    """
    timestamp: datetime
    event_type: str
    category: str
    pid: int
    ppid: int
    uid: int
    gid: int
    username: str
    comm: str
    filename: str
    addr_v4: str
    port: int
    protocol: int
    target_uid: int
    target_gid: int
    ptrace_request: int
    target_pid: int
    flags: int
    severity: Severity = "LOW"
    detection: str | None = None
    detection_id: str | None = None
    mitre_id: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


def _decode_comm(raw: bytes) -> str:
    """
    Decode a null-terminated comm field
    """
    return raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")


def _decode_filename(raw: bytes) -> str:
    """
    Decode a null-terminated filename field
    """
    return raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")


def _ipv4_to_str(addr: int) -> str:
    """
    Convert a 32-bit network-order IPv4 address to string
    """
    if addr == 0:
        return ""
    return ".".join(str((addr >> (i * 8)) & 0xFF) for i in range(4))


_UID_CACHE: dict[int, str] = {}


def _resolve_username(uid: int) -> str:
    """
    Resolve UID to username with caching
    """
    if uid in _UID_CACHE:
        return _UID_CACHE[uid]

    try:
        name = pwd.getpwuid(uid).pw_name
    except KeyError:
        name = str(uid)

    _UID_CACHE[uid] = name
    return name


def _boot_time_ns() -> int:
    """
    Read system boot time for timestamp conversion
    """
    stat_path = Path("/proc/stat")
    if not stat_path.exists():
        return 0

    for line in stat_path.read_text().splitlines():
        if line.startswith("btime"):
            return int(line.split()[1]) * 1_000_000_000
    return 0


_BOOT_NS = _boot_time_ns()


def _ktime_to_datetime(ktime_ns: int) -> datetime:
    """
    Convert kernel monotonic timestamp to wall clock
    """
    epoch_ns = _BOOT_NS + ktime_ns
    return datetime.fromtimestamp(epoch_ns / 1_000_000_000,
                                  tz=timezone.utc)


def parse_raw_event(
    ctx: Any,
    data: Any,
    size: int,
) -> TracerEvent:
    """
    Convert raw ring buffer bytes to a TracerEvent
    """
    raw = ctypes.cast(data, ctypes.POINTER(RawEvent)).contents

    etype = raw.event_type
    type_name = EVENT_TYPE_NAMES.get(etype, f"unknown_{etype}")
    category = EVENT_TYPE_CATEGORIES.get(etype, "unknown")

    return TracerEvent(
        timestamp=_ktime_to_datetime(raw.timestamp_ns),
        event_type=type_name,
        category=category,
        pid=raw.pid,
        ppid=raw.ppid,
        uid=raw.uid,
        gid=raw.gid,
        username=_resolve_username(raw.uid),
        comm=_decode_comm(raw.comm),
        filename=_decode_filename(raw.filename),
        addr_v4=_ipv4_to_str(raw.addr_v4),
        port=raw.port,
        protocol=raw.protocol,
        target_uid=raw.target_uid,
        target_gid=raw.target_gid,
        ptrace_request=raw.ptrace_request,
        target_pid=raw.target_pid,
        flags=raw.flags,
    )


def _resolve_parent_comm(ppid: int) -> str:
    """
    Read parent process name from /proc
    """
    comm_path = Path(f"/proc/{ppid}/comm")
    try:
        return comm_path.read_text().strip()
    except (FileNotFoundError, PermissionError):
        return ""


def enrich_event(event: TracerEvent) -> TracerEvent:
    """
    Add additional context from /proc filesystem
    """
    parent_comm = _resolve_parent_comm(event.ppid)
    if parent_comm:
        event.extra["parent_comm"] = parent_comm
    return event


def should_include(
    event: TracerEvent,
    min_severity: Severity,
    pid_filter: int | None,
    comm_filter: str | None,
    tracer_type: TracerType,
    detections_only: bool,
) -> bool:
    """
    Determine if an event passes all active filters
    """
    if detections_only and event.detection is None:
        return False

    sev_val = SEVERITY_ORDER.get(event.severity, 0)
    min_val = SEVERITY_ORDER.get(min_severity, 0)
    if sev_val < min_val:
        return False

    if pid_filter is not None and event.pid != pid_filter:
        return False

    if (comm_filter is not None and event.comm != comm_filter):
        return False

    if tracer_type != "all" and event.category != tracer_type:
        return False

    return True
