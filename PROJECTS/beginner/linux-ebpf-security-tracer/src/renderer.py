"""
©AngelaMos | 2026
renderer.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import IO, Any, TextIO

from rich.console import Console
from rich.table import Table
from rich.text import Text

from .config import (
    SEVERITY_COLORS,
    OutputFormat,
)
from .processor import TracerEvent


def _event_to_dict(event: TracerEvent) -> dict[str, Any]:
    """
    Serialize a TracerEvent to a JSON-compatible dict
    """
    d: dict[str, Any] = {
        "timestamp": event.timestamp.isoformat(),
        "event_type": event.event_type,
        "category": event.category,
        "pid": event.pid,
        "ppid": event.ppid,
        "uid": event.uid,
        "username": event.username,
        "comm": event.comm,
        "severity": event.severity,
    }

    if event.filename:
        d["filename"] = event.filename

    if event.addr_v4:
        d["dest_ip"] = event.addr_v4
        d["dest_port"] = event.port

    if event.event_type in ("setuid", "setgid"):
        d["target_uid"] = event.target_uid
        d["target_gid"] = event.target_gid

    if event.event_type == "ptrace":
        d["ptrace_request"] = event.ptrace_request
        d["target_pid"] = event.target_pid

    if event.detection:
        d["detection"] = event.detection
        d["detection_id"] = event.detection_id
        d["mitre_id"] = event.mitre_id

    parent_comm = event.extra.get("parent_comm")
    if parent_comm:
        d["parent_comm"] = parent_comm

    return d


class JsonRenderer:
    """
    Outputs one JSON object per line
    """

    def __init__(
        self,
        stream: TextIO = sys.stdout,
    ) -> None:
        """
        Initialize with output stream
        """
        self._stream = stream

    def render(self, event: TracerEvent) -> None:
        """
        Write a single event as JSON
        """
        d = _event_to_dict(event)
        self._stream.write(json.dumps(d) + "\n")
        self._stream.flush()


class LiveRenderer:
    """
    Color-coded streaming output using Rich
    """

    def __init__(
        self,
        console: Console | None = None,
    ) -> None:
        """
        Initialize with Rich console
        """
        self._console = console or Console()

    def render(self, event: TracerEvent) -> None:
        """
        Print a color-coded event line
        """
        ts = event.timestamp.strftime("%H:%M:%S")
        color = SEVERITY_COLORS.get(event.severity, "white")

        sev = Text(f"{event.severity:8s}", style=color)

        detail = self._format_detail(event)

        line = Text()
        line.append(f"[{ts}] ")
        line.append_text(sev)
        line.append(f" {event.event_type:14s} ")
        line.append(f"pid={event.pid} "
                    f"comm={event.comm} ")
        if detail:
            line.append(detail)

        if event.detection:
            det_text = Text(
                f" [{event.detection}]",
                style="bold magenta",
            )
            line.append_text(det_text)

        self._console.print(line)

    def _format_detail(
        self,
        event: TracerEvent,
    ) -> str:
        """
        Build detail string based on event type
        """
        if event.filename:
            return event.filename
        if event.addr_v4:
            return f"{event.addr_v4}:{event.port}"
        if event.target_uid:
            return f"uid->{event.target_uid}"
        if event.ptrace_request:
            return (f"req={event.ptrace_request} "
                    f"target={event.target_pid}")
        return ""


class TableRenderer:
    """
    Periodic table summaries using Rich
    """

    def __init__(
        self,
        console: Console | None = None,
    ) -> None:
        """
        Initialize with Rich console and event buffer
        """
        self._console = console or Console()
        self._buffer: list[TracerEvent] = []
        self._flush_count = 20

    def render(self, event: TracerEvent) -> None:
        """
        Buffer events and flush as table periodically
        """
        self._buffer.append(event)
        if len(self._buffer) >= self._flush_count:
            self._flush()

    def _flush(self) -> None:
        """
        Render buffered events as a Rich table
        """
        if not self._buffer:
            return

        table = Table(
            title="eBPF Security Events",
            show_lines=False,
        )
        table.add_column("Time", width=8)
        table.add_column("Severity", width=8)
        table.add_column("Type", width=12)
        table.add_column("PID", width=7)
        table.add_column("Comm", width=15)
        table.add_column("Detail", min_width=20)
        table.add_column("Detection", width=18)

        for ev in self._buffer:
            color = SEVERITY_COLORS.get(ev.severity, "white")
            ts = ev.timestamp.strftime("%H:%M:%S")
            detail = ""
            if ev.filename:
                detail = ev.filename
            elif ev.addr_v4:
                detail = f"{ev.addr_v4}:{ev.port}"

            table.add_row(
                ts,
                Text(ev.severity, style=color),
                ev.event_type,
                str(ev.pid),
                ev.comm,
                detail,
                ev.detection or "",
            )

        self._console.print(table)
        self._buffer.clear()

    def finalize(self) -> None:
        """
        Flush remaining events on shutdown
        """
        self._flush()


class FileRenderer:
    """
    Append JSON events to a file
    """

    def __init__(self, path: Path) -> None:
        """
        Initialize with output file path
        """
        self._path = path
        self._fh: IO[str] | None = None

    def render(self, event: TracerEvent) -> None:
        """
        Append a single event as JSON to the file
        """
        if self._fh is None:
            self._fh = open(self._path, "a")

        d = _event_to_dict(event)
        self._fh.write(json.dumps(d) + "\n")
        self._fh.flush()

    def close(self) -> None:
        """
        Close the output file handle
        """
        if self._fh is not None:
            self._fh.close()
            self._fh = None


def create_renderer(
    fmt: OutputFormat, ) -> JsonRenderer | LiveRenderer | TableRenderer:
    """
    Factory for the appropriate renderer
    """
    if fmt == "json":
        return JsonRenderer()
    if fmt == "table":
        return TableRenderer()
    return LiveRenderer()
