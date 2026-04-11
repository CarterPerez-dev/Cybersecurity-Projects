"""
©AngelaMos | 2026
detector.py
"""
from __future__ import annotations

import time
from collections import deque

from .config import (
    CORRELATION_WINDOW_SEC,
    CREDENTIAL_ACCESS_ALLOWLIST,
    CREDENTIAL_PATHS,
    DETECTION_RULES,
    LOG_PATHS,
    MAX_EVENTS_PER_PID,
    PERSISTENCE_CRON_PATHS,
    PERSISTENCE_SYSTEMD_PATHS,
    PTRACE_ATTACH,
    PTRACE_SEIZE,
    PTRACE_SETREGS,
    SENSITIVE_READ_PATHS,
    SHELL_BINARIES,
    SWEEP_INTERVAL,
    DetectionRule,
)
from .processor import TracerEvent


def _apply_detection(
    event: TracerEvent,
    rule: DetectionRule,
) -> TracerEvent:
    """
    Stamp a detection onto an event
    """
    event.severity = rule.severity
    event.detection = rule.name
    event.detection_id = rule.rule_id
    event.mitre_id = rule.mitre_id
    return event


def _path_matches(
    filepath: str,
    patterns: tuple[str, ...],
) -> bool:
    """
    Check if a filepath starts with any pattern
    """
    for pattern in patterns:
        if filepath.startswith(pattern):
            return True
    return False


def _path_contains(
    filepath: str,
    patterns: tuple[str, ...],
) -> bool:
    """
    Check if a filepath contains any pattern
    """
    for pattern in patterns:
        if pattern in filepath:
            return True
    return False


O_WRONLY = 1
O_RDWR = 2
O_TRUNC = 512
O_CREAT = 64


def _is_write_flags(flags: int) -> bool:
    """
    Determine if openat flags indicate a write operation
    """
    return bool(flags & (O_WRONLY | O_RDWR))


class DetectionEngine:
    """
    Evaluates events against detection rules
    """

    def __init__(self) -> None:
        """
        Initialize event history for correlation
        """
        self._history: dict[int, deque[TracerEvent]] = {}
        self._event_count = 0

    def _get_history(
        self,
        pid: int,
    ) -> deque[TracerEvent]:
        """
        Get or create the event deque for a PID
        """
        if pid not in self._history:
            self._history[pid] = deque(maxlen=MAX_EVENTS_PER_PID)
        return self._history[pid]

    def _prune_history(self, pid: int) -> None:
        """
        Remove stale events outside the correlation window
        """
        if pid not in self._history:
            return

        cutoff = time.monotonic() - CORRELATION_WINDOW_SEC
        hist = self._history[pid]

        while hist and hist[0].extra.get("_mono_time", 0) < cutoff:
            hist.popleft()

        if not hist:
            del self._history[pid]

    def _sweep_stale(self) -> None:
        """
        Remove all PIDs with only expired events
        """
        cutoff = time.monotonic() - CORRELATION_WINDOW_SEC
        stale_pids = [
            pid for pid, hist in self._history.items()
            if not hist or hist[-1].extra.get("_mono_time", 0) < cutoff
        ]
        for pid in stale_pids:
            del self._history[pid]

    def evaluate(
        self,
        event: TracerEvent,
    ) -> TracerEvent:
        """
        Run all detection rules against an event
        """
        event.extra["_mono_time"] = time.monotonic()

        det = self._check_stateless(event)
        if det is None:
            det = self._check_stateful(event)

        hist = self._get_history(event.pid)
        hist.append(event)
        self._prune_history(event.pid)

        self._event_count += 1
        if self._event_count % SWEEP_INTERVAL == 0:
            self._sweep_stale()

        if det is not None:
            return _apply_detection(event, det)
        return event

    def _check_stateless(
        self,
        event: TracerEvent,
    ) -> DetectionRule | None:
        """
        Check single-event detection rules
        """
        if event.event_type == "setuid":
            if event.target_uid == 0 and event.uid != 0:
                return DETECTION_RULES["D001"]

        if event.event_type == "openat":
            filename = event.filename

            if _path_matches(filename, SENSITIVE_READ_PATHS):
                if (event.uid != 0 and not _is_write_flags(event.flags)):
                    return DETECTION_RULES["D002"]

            if _path_contains(filename, CREDENTIAL_PATHS):
                if event.comm not in CREDENTIAL_ACCESS_ALLOWLIST:
                    return DETECTION_RULES["D003"]

            if _is_write_flags(event.flags):
                if _path_matches(filename, PERSISTENCE_CRON_PATHS):
                    return DETECTION_RULES["D007"]

                if _path_matches(filename, PERSISTENCE_SYSTEMD_PATHS):
                    return DETECTION_RULES["D008"]

            if _path_matches(filename, LOG_PATHS):
                if event.flags & O_TRUNC:
                    return DETECTION_RULES["D009"]

        if event.event_type == "unlinkat":
            if _path_matches(event.filename, LOG_PATHS):
                return DETECTION_RULES["D009"]

        if event.event_type == "ptrace":
            if event.ptrace_request in (
                    PTRACE_ATTACH,
                    PTRACE_SEIZE,
                    PTRACE_SETREGS,
            ):
                return DETECTION_RULES["D004"]

        if event.event_type == "init_module":
            return DETECTION_RULES["D005"]

        if event.event_type == "mount":
            return DETECTION_RULES["D010"]

        return None

    def _check_stateful(
        self,
        event: TracerEvent,
    ) -> DetectionRule | None:
        """
        Check multi-event correlation rules
        """
        if event.event_type == "execve":
            if event.comm not in SHELL_BINARIES:
                return None

            hist = self._get_history(event.pid)
            has_connect = any(e.event_type == "connect" for e in hist)

            if not has_connect:
                ppid_hist = self._history.get(event.ppid)
                if ppid_hist:
                    has_connect = any(e.event_type == "connect"
                                      for e in ppid_hist)

            if has_connect:
                return DETECTION_RULES["D006"]

        if event.event_type == "connect":
            hist = self._get_history(event.pid)
            has_shell = any(
                e.event_type == "execve" and e.comm in SHELL_BINARIES
                for e in hist)
            if has_shell:
                return DETECTION_RULES["D006"]

        return None
