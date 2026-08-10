"""
©AngelaMos | 2026
session.py
"""

import secrets
import time
from collections import deque
from dataclasses import dataclass, field

from not_sandboxed import config


def _new_secret() -> str:
    token = secrets.token_hex(config.ARENA_CANARY_BYTES).upper()
    return f"{config.ARENA_CANARY_LABEL}-{token}"


@dataclass
class Session:
    """
    One visitor's isolated game, holding a secret nobody else can win
    """

    session_id: str
    secret: str
    attempts: int = 0
    bypasses: list[dict[str, str]] = field(default_factory = list)
    recent: deque[float] = field(default_factory = deque)


class RateLimitedError(Exception):
    """
    Raised when a session is asking faster than the arena allows
    """


class SessionStore:
    """
    Per-visitor state with no shared mutable data between sessions
    """
    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}

    def create(self) -> Session:
        """
        Start a session with its own freshly generated secret
        """
        if len(self._sessions) >= config.ARENA_MAX_SESSIONS:
            oldest = next(iter(self._sessions))
            del self._sessions[oldest]

        session = Session(
            session_id = secrets.token_urlsafe(
                config.ARENA_SESSION_ID_BYTES
            ),
            secret = _new_secret(),
        )
        self._sessions[session.session_id] = session
        return session

    def get(self, session_id: str) -> Session | None:
        """
        Look up a session without creating one
        """
        return self._sessions.get(session_id)

    def charge(self, session: Session, now: float) -> None:
        """
        Count one attempt against both the window and the session
        budget, refusing rather than throttling silently
        """
        if session.attempts >= config.ARENA_MAX_ATTEMPTS_PER_SESSION:
            raise RateLimitedError(config.ERROR_SESSION_EXHAUSTED)

        cutoff = now - config.ARENA_RATE_WINDOW_SECONDS
        while session.recent and session.recent[0] < cutoff:
            session.recent.popleft()

        if len(session.recent) >= config.ARENA_MAX_ATTEMPTS_PER_WINDOW:
            raise RateLimitedError(config.ERROR_RATE_LIMITED)

        session.recent.append(now)
        session.attempts += 1

    def clock(self) -> float:
        """
        The monotonic clock the rate limiter measures against
        """
        return time.monotonic()
