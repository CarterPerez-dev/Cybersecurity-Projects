"""
©AngelaMos | 2026
tailer.py
"""

import asyncio
import logging
import os
from io import TextIOWrapper
from pathlib import Path

from watchdog.events import (
    FileCreatedEvent,
    FileModifiedEvent,
    FileMovedEvent,
    FileSystemEventHandler,
)
from watchdog.observers import Observer

logger = logging.getLogger(__name__)


class _LogHandler(FileSystemEventHandler):
    """
    Watchdog event handler that detects modifications and log rotation
    for a single target file, pushing new lines into an asyncio.Queue.
    """

    def __init__(
        self,
        target: str,
        queue: asyncio.Queue[str | None],
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        super().__init__()
        self._target = target
        self._queue = queue
        self._loop = loop
        self._file: TextIOWrapper | None = None
        self._inode: int | None = None
        self._open_target()

    def _open_target(self) -> None:
        """
        Open the target log file and seek to the end.
        """
        try:
            self._file = open(self._target, encoding="utf-8", errors="replace")  # noqa: SIM115
            self._file.seek(0, os.SEEK_END)
            self._inode = os.stat(self._target).st_ino
            logger.info("Tailing %s (inode %s)", self._target, self._inode)
        except FileNotFoundError:
            logger.warning("Log file %s not found — waiting for creation", self._target)
            self._file = None
            self._inode = None

    def _read_new_lines(self) -> None:
        """
        Read all new complete lines from the current file position.
        """
        if self._file is None:
            return

        for line in self._file:
            stripped = line.rstrip("\n\r")
            if stripped:
                self._loop.call_soon_threadsafe(self._queue.put_nowait, stripped)

    def _handle_rotation(self) -> None:
        """
        Finish reading the old file, then reopen the target at position 0.
        """
        self._read_new_lines()

        if self._file is not None:
            self._file.close()

        try:
            self._file = open(self._target, encoding="utf-8", errors="replace")  # noqa: SIM115
            self._inode = os.stat(self._target).st_ino
            logger.info("Rotated to new %s (inode %s)", self._target, self._inode)
        except FileNotFoundError:
            self._file = None
            self._inode = None

    def _inode_changed(self) -> bool:
        """
        Check whether the target file's inode differs from the one we opened.
        """
        try:
            current_inode = os.stat(self._target).st_ino
            return current_inode != self._inode
        except FileNotFoundError:
            return False

    def on_modified(self, event: FileModifiedEvent) -> None:  # type: ignore[override]
        """
        Handle new data appended to the log file.
        """
        if not isinstance(event, FileModifiedEvent) or event.is_directory:
            return

        if Path(str(event.src_path)).resolve() != Path(self._target).resolve():
            return

        if self._inode_changed():
            self._handle_rotation()
            return

        self._read_new_lines()

    def on_moved(self, event: FileMovedEvent) -> None:  # type: ignore[override]
        """
        Handle log rotation via rename (access.log -> access.log.1).
        """
        if not isinstance(event, FileMovedEvent):
            return

        if Path(str(event.src_path)).resolve() == Path(self._target).resolve():
            logger.info("Log rotated: %s -> %s", event.src_path, event.dest_path)
            self._handle_rotation()

    def on_created(self, event: FileCreatedEvent) -> None:  # type: ignore[override]
        """
        Handle log rotation where a new file is created at the target path.
        """
        if not isinstance(event, FileCreatedEvent) or event.is_directory:
            return

        if Path(str(event.src_path)).resolve() == Path(self._target).resolve():
            logger.info("New log file created: %s", event.src_path)
            self._handle_rotation()

    def close(self) -> None:
        """
        Close the underlying file handle.
        """
        if self._file is not None:
            self._file.close()
            self._file = None


class LogTailer:
    """
    Watchdog-based nginx log tailer that pushes raw lines
    into an asyncio.Queue for downstream processing.
    """

    def __init__(
        self,
        log_path: str,
        queue: asyncio.Queue[str | None],
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        self._log_path = log_path
        self._handler = _LogHandler(log_path, queue, loop)
        self._observer = Observer()
        self._started = False

    def start(self) -> None:
        """
        Begin watching the log file's parent directory for changes.
        """
        watch_dir = str(Path(self._log_path).resolve().parent)
        self._observer.schedule(self._handler, watch_dir, recursive=False)
        self._observer.start()
        self._started = True
        logger.info("LogTailer started — watching %s", watch_dir)

    def stop(self) -> None:
        """
        Stop the watchdog observer and close file handles.
        """
        if self._started:
            self._observer.stop()
            self._observer.join(timeout=5)
            self._started = False
        self._handler.close()
        logger.info("LogTailer stopped")

    @property
    def is_active(self) -> bool:
        """
        Whether the tailer is currently running.
        """
        return self._started and self._observer.is_alive()
