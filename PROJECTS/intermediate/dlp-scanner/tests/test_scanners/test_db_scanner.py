"""
©AngelaMos | 2026
test_db_scanner.py
"""


import sqlite3
from pathlib import Path
from typing import Any

import pytest

from dlp_scanner.config import ScanConfig
from dlp_scanner.detectors.registry import DetectorRegistry
from dlp_scanner.scanners.db_scanner import (
    DatabaseScanner,
    _extract_mongo_strings,
)


@pytest.fixture
def sqlite_db_with_pii(temp_dir: Path) -> str:
    """
    Provide a SQLite database containing PII test data
    """
    db_path = temp_dir / "test.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "CREATE TABLE employees ("
        "id INTEGER PRIMARY KEY, "
        "name TEXT, "
        "ssn TEXT, "
        "email TEXT, "
        "salary REAL)"
    )
    conn.execute(
        "INSERT INTO employees "
        "(name, ssn, email, salary) "
        "VALUES (?, ?, ?, ?)",
        (
            "John Doe",
            "456-78-9012",
            "john@example.com",
            75000.0,
        ),
    )
    conn.execute(
        "INSERT INTO employees "
        "(name, ssn, email, salary) "
        "VALUES (?, ?, ?, ?)",
        (
            "Jane Smith",
            "234-56-7890",
            "jane@example.com",
            85000.0,
        ),
    )
    conn.commit()
    conn.close()
    return f"sqlite:///{db_path}"


@pytest.fixture
def sqlite_db_empty(temp_dir: Path) -> str:
    """
    Provide a SQLite database with an empty table
    """
    db_path = temp_dir / "empty.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "CREATE TABLE logs ("
        "id INTEGER PRIMARY KEY, "
        "message TEXT)"
    )
    conn.commit()
    conn.close()
    return f"sqlite:///{db_path}"


@pytest.fixture
def db_scanner() -> DatabaseScanner:
    """
    Provide a default DatabaseScanner instance
    """
    config = ScanConfig()
    registry = DetectorRegistry()
    return DatabaseScanner(config = config, registry = registry)


class TestDatabaseScanner:
    def test_sqlite_scan_finds_pii(
        self,
        db_scanner: DatabaseScanner,
        sqlite_db_with_pii: str,
    ) -> None:
        result = db_scanner.scan(sqlite_db_with_pii)
        assert result.targets_scanned > 0
        assert len(result.findings) > 0

    def test_sqlite_scan_finds_ssn(
        self,
        db_scanner: DatabaseScanner,
        sqlite_db_with_pii: str,
    ) -> None:
        result = db_scanner.scan(sqlite_db_with_pii)
        ssn_findings = [
            f for f in result.findings if f.rule_id == "PII_SSN"
        ]
        assert len(ssn_findings) > 0

    def test_sqlite_scan_empty_table(
        self,
        db_scanner: DatabaseScanner,
        sqlite_db_empty: str,
    ) -> None:
        result = db_scanner.scan(sqlite_db_empty)
        assert result.targets_scanned > 0
        assert len(result.findings) == 0

    def test_findings_have_database_source(
        self,
        db_scanner: DatabaseScanner,
        sqlite_db_with_pii: str,
    ) -> None:
        result = db_scanner.scan(sqlite_db_with_pii)
        for finding in result.findings:
            assert (finding.location.source_type == "database")

    def test_findings_have_table_name(
        self,
        db_scanner: DatabaseScanner,
        sqlite_db_with_pii: str,
    ) -> None:
        result = db_scanner.scan(sqlite_db_with_pii)
        for finding in result.findings:
            assert (finding.location.table_name == "employees")

    def test_unsupported_scheme_errors(
        self,
        db_scanner: DatabaseScanner,
    ) -> None:
        result = db_scanner.scan("ftp://localhost/db")
        assert len(result.errors) > 0

    def test_completed_at_is_set(
        self,
        db_scanner: DatabaseScanner,
        sqlite_db_with_pii: str,
    ) -> None:
        result = db_scanner.scan(sqlite_db_with_pii)
        assert result.scan_completed_at is not None

    def test_findings_have_remediation(
        self,
        db_scanner: DatabaseScanner,
        sqlite_db_with_pii: str,
    ) -> None:
        result = db_scanner.scan(sqlite_db_with_pii)
        for finding in result.findings:
            assert finding.remediation

    def test_table_exclude_filter(
        self,
        temp_dir: Path,
    ) -> None:
        db_path = temp_dir / "filter.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE users "
                     "(id INTEGER, ssn TEXT)")
        conn.execute("INSERT INTO users "
                     "VALUES (1, '123-45-6789')")
        conn.execute("CREATE TABLE audit_log "
                     "(id INTEGER, note TEXT)")
        conn.execute("INSERT INTO audit_log "
                     "VALUES (1, '987-65-4321')")
        conn.commit()
        conn.close()

        config = ScanConfig()
        config.database.exclude_tables = ["audit_log"]
        registry = DetectorRegistry()
        scanner = DatabaseScanner(config = config, registry = registry)

        result = scanner.scan(f"sqlite:///{db_path}")
        assert result.targets_scanned == 1

    def test_table_include_filter(
        self,
        temp_dir: Path,
    ) -> None:
        db_path = temp_dir / "include.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE users "
                     "(id INTEGER, ssn TEXT)")
        conn.execute("INSERT INTO users "
                     "VALUES (1, '123-45-6789')")
        conn.execute("CREATE TABLE logs "
                     "(id INTEGER, msg TEXT)")
        conn.execute("INSERT INTO logs "
                     "VALUES (1, '987-65-4321')")
        conn.commit()
        conn.close()

        config = ScanConfig()
        config.database.include_tables = ["users"]
        registry = DetectorRegistry()
        scanner = DatabaseScanner(config = config, registry = registry)

        result = scanner.scan(f"sqlite:///{db_path}")
        assert result.targets_scanned == 1


class TestExtractMongoStrings:
    def test_simple_strings(self) -> None:
        doc: dict[str,
                  Any] = {
                      "name": "John",
                      "email": "john@test.com",
                  }
        parts: list[str] = []
        _extract_mongo_strings(doc, parts)
        assert len(parts) == 2

    def test_nested_doc(self) -> None:
        doc: dict[str,
                  Any] = {
                      "user": {
                          "name": "Jane",
                          "ssn": "123-45-6789",
                      }
                  }
        parts: list[str] = []
        _extract_mongo_strings(doc, parts)
        assert any("user.name" in p for p in parts)
        assert any("user.ssn" in p for p in parts)

    def test_skips_id_field(self) -> None:
        doc: dict[str,
                  Any] = {
                      "_id": "abc123",
                      "name": "Test",
                  }
        parts: list[str] = []
        _extract_mongo_strings(doc, parts)
        assert len(parts) == 1
        assert "name" in parts[0]

    def test_list_values(self) -> None:
        doc: dict[str, Any] = {"emails": ["a@b.com", "c@d.com"]}
        parts: list[str] = []
        _extract_mongo_strings(doc, parts)
        assert len(parts) == 2

    def test_empty_strings_skipped(self) -> None:
        doc: dict[str,
                  Any] = {
                      "name": "",
                      "bio": "  ",
                  }
        parts: list[str] = []
        _extract_mongo_strings(doc, parts)
        assert len(parts) == 0

    def test_nested_list_of_dicts(self) -> None:
        doc: dict[str,
                  Any] = {
                      "records": [
                          {
                              "value": "secret"
                          },
                          {
                              "value": "data"
                          },
                      ]
                  }
        parts: list[str] = []
        _extract_mongo_strings(doc, parts)
        assert len(parts) == 2
