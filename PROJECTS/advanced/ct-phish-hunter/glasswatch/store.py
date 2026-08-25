"""SQLite-backed findings store.

Stdlib sqlite3, no server to stand up. A watcher polling a busy CT log
sees the same domain reissued across multiple certs constantly (renewals,
SAN churn, multiple CAs), so findings are deduplicated on
(domain, brand) and the row's `seen_count` and `last_seen` are bumped
instead of inserting a duplicate alert every poll.
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

from glasswatch.detect import Finding

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    brand TEXT NOT NULL,
    score INTEGER NOT NULL,
    severity TEXT NOT NULL,
    reasons TEXT NOT NULL,
    log_url TEXT,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    seen_count INTEGER NOT NULL DEFAULT 1,
    UNIQUE(domain, brand)
);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_last_seen ON findings(last_seen);
"""


class FindingsStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> FindingsStore:
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def record(self, finding: Finding, log_url: str | None = None) -> bool:
        """Insert or bump a finding. Returns True if this is a brand new
        (domain, brand) pair the caller should alert on, False if it was
        already known and only the counters were updated.
        """
        now = time.time()
        reasons_str = ",".join(finding.reasons)
        self._conn.execute(
            """
            INSERT INTO findings (domain, brand, score, severity, reasons, log_url, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(domain, brand) DO UPDATE SET
                score = excluded.score,
                severity = excluded.severity,
                reasons = excluded.reasons,
                last_seen = excluded.last_seen,
                seen_count = seen_count + 1
            """,
            (finding.domain, finding.brand, finding.score, finding.severity,
             reasons_str, log_url, now, now),
        )
        self._conn.commit()
        return self._was_insert(finding.domain, finding.brand)

    def _was_insert(self, domain: str, brand: str) -> bool:
        row = self._conn.execute(
            "SELECT seen_count FROM findings WHERE domain = ? AND brand = ?",
            (domain, brand),
        ).fetchone()
        return row is not None and row["seen_count"] == 1

    def list_findings(self, severity: str | None = None, limit: int = 500) -> list[sqlite3.Row]:
        if severity:
            rows = self._conn.execute(
                "SELECT * FROM findings WHERE severity = ? ORDER BY last_seen DESC LIMIT ?",
                (severity, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM findings ORDER BY last_seen DESC LIMIT ?", (limit,),
            ).fetchall()
        return rows

    def count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
