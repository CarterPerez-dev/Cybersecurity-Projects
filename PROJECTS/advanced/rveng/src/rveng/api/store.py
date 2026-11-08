"""
©AngelaMos | 2026
store.py
"""

import json
import logging
import sqlite3
import threading
from pathlib import Path
from typing import Protocol

from rveng.engine import patch
from rveng.engine.challenge import (
    Challenge,
    FoundValue,
    IdentifiedSymbol,
    PatchedBytes,
)


log = logging.getLogger(__name__)

MANIFEST = "challenge.json"
TARGET = "target"
SOURCE = "source.c"

DATA_DIR = "data"
DB_FILENAME = "progress.db"
DEFAULT_DB_PATH = Path(__file__).resolve().parents[3] / DATA_DIR / DB_FILENAME
IN_MEMORY_DB = ":memory:"
SOLVED_TABLE = "solved"

CAT_FOUND_VALUE = "found_value"
CAT_IDENTIFIED_SYMBOL = "identified_symbol"
CAT_PATCHED_BYTES = "patched_bytes"


class ChallengeError(ValueError):
    """
    Raised when a challenge asset directory is malformed
    """


def _build_answer(spec: dict, binary: bytes):
    category = spec.get("category")
    try:
        if category == CAT_FOUND_VALUE:
            return FoundValue(spec["expected"])
        if category == CAT_IDENTIFIED_SYMBOL:
            return IdentifiedSymbol(spec["name"])
        if category == CAT_PATCHED_BYTES:
            offset = spec["offset"]
            replacement = bytes.fromhex(spec["patch"])
            known_good = patch.apply(binary, offset, replacement)
            return PatchedBytes(offset = offset, known_good = known_good)
    except (KeyError, ValueError) as exc:
        raise ChallengeError(f"bad {category} answer spec: {exc}") from exc
    raise ChallengeError(f"unknown answer category: {category}")


def load_challenge(directory: Path) -> Challenge:
    """
    Load one challenge from its asset directory
    """
    manifest_path = directory / MANIFEST
    if not manifest_path.is_file():
        raise ChallengeError(f"no manifest in {directory}")
    try:
        manifest = json.loads(manifest_path.read_text())
        binary = (directory / TARGET).read_bytes()
        source = (directory / SOURCE).read_text()
        return Challenge(
            id = manifest["id"],
            module = manifest["module"],
            title = manifest["title"],
            mission = manifest["mission"],
            binary = binary,
            source = source,
            answer = _build_answer(manifest["answer"],
                                   binary),
        )
    except (json.JSONDecodeError, KeyError, OSError) as exc:
        raise ChallengeError(f"malformed challenge in {directory}: {exc}") from exc


class ChallengeStore:
    """
    An in-memory registry of loaded challenges keyed by id
    """
    def __init__(self, challenges: list[Challenge]):
        self._by_id = {c.id: c for c in challenges}

    def list(self) -> list[Challenge]:
        return sorted(self._by_id.values(), key = lambda c: c.id)

    def get(self, challenge_id: str) -> Challenge | None:
        return self._by_id.get(challenge_id)


def load_store(root: Path) -> ChallengeStore:
    """
    Load every challenge directory under root into a store
    """
    challenges = []
    for directory in sorted(root.iterdir()):
        if not (directory / MANIFEST).is_file():
            continue
        try:
            challenges.append(load_challenge(directory))
        except ChallengeError as exc:
            log.warning("skipping challenge: %s", exc)
    return ChallengeStore(challenges)


class ProgressStore(Protocol):
    """
    Persistence boundary for solved-challenge tracking
    """
    def mark_solved(self, session: str, challenge_id: str) -> None:
        ...

    def solved(self, session: str) -> set[str]:
        ...


class InMemoryProgress:
    """
    A process-local progress store used for tests and ephemeral runs
    """
    def __init__(self):
        self._solved: dict[str, set[str]] = {}

    def mark_solved(self, session: str, challenge_id: str) -> None:
        self._solved.setdefault(session, set()).add(challenge_id)

    def solved(self, session: str) -> set[str]:
        return set(self._solved.get(session, set()))


class SqliteProgress:
    """
    A SQLite-backed progress store durable across restarts
    """
    def __init__(self, path: Path | str = DEFAULT_DB_PATH):
        self._path = str(path)
        if self._path != IN_MEMORY_DB:
            Path(self._path).parent.mkdir(parents = True, exist_ok = True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self._path, check_same_thread = False)
        self._conn.execute(
            f"CREATE TABLE IF NOT EXISTS {SOLVED_TABLE} ("
            "session TEXT NOT NULL, "
            "challenge_id TEXT NOT NULL, "
            "PRIMARY KEY (session, challenge_id))"
        )
        self._conn.commit()

    def mark_solved(self, session: str, challenge_id: str) -> None:
        with self._lock:
            self._conn.execute(
                f"INSERT OR IGNORE INTO {SOLVED_TABLE} "
                "(session, challenge_id) VALUES (?, ?)",
                (session,
                 challenge_id)
            )
            self._conn.commit()

    def solved(self, session: str) -> set[str]:
        with self._lock:
            rows = self._conn.execute(
                f"SELECT challenge_id FROM {SOLVED_TABLE} "
                "WHERE session = ?",
                (session,
                 )
            ).fetchall()
        return {row[0] for row in rows}
