"""
©AngelaMos | 2026
db_scanner.py
"""


import asyncio
from datetime import datetime, UTC
from typing import Any
from urllib.parse import urlparse

import structlog

from dlp_scanner.config import ScanConfig
from dlp_scanner.constants import (
    TEXT_DB_COLUMN_TYPES_MYSQL,
    TEXT_DB_COLUMN_TYPES_PG,
)
from dlp_scanner.detectors.base import DetectorMatch
from dlp_scanner.detectors.registry import DetectorRegistry
from dlp_scanner.models import (
    Location,
    ScanResult,
)
from dlp_scanner.scoring import match_to_finding


log = structlog.get_logger()

POSTGRES_SCHEMES: frozenset[str] = frozenset({
    "postgresql",
    "postgres",
})
MYSQL_SCHEMES: frozenset[str] = frozenset({
    "mysql",
    "mysql+aiomysql",
})
MONGODB_SCHEMES: frozenset[str] = frozenset({
    "mongodb",
    "mongodb+srv",
})
SQLITE_SCHEMES: frozenset[str] = frozenset({
    "sqlite",
})


class DatabaseScanner:
    """
    Scans database tables for sensitive data in text columns
    """
    def __init__(
        self,
        config: ScanConfig,
        registry: DetectorRegistry,
    ) -> None:
        self._db_config = config.database
        self._detection_config = config.detection
        self._redaction_style = config.output.redaction_style
        self._registry = registry

    def scan(self, target: str) -> ScanResult:
        """
        Scan a database identified by connection URI
        """
        return asyncio.run(self._scan_async(target))

    async def _scan_async(
        self,
        connection_uri: str,
    ) -> ScanResult:
        """
        Dispatch to the appropriate database scanner
        """
        result = ScanResult()
        parsed = urlparse(connection_uri)
        scheme = parsed.scheme.lower()

        try:
            if scheme in POSTGRES_SCHEMES:
                await self._scan_postgres(connection_uri, result)
            elif scheme in MYSQL_SCHEMES:
                await self._scan_mysql(connection_uri, result)
            elif scheme in MONGODB_SCHEMES:
                await self._scan_mongodb(connection_uri, result)
            elif scheme in SQLITE_SCHEMES:
                await self._scan_sqlite(connection_uri, result)
            else:
                result.errors.append(
                    f"Unsupported database scheme: "
                    f"{scheme}"
                )
        except Exception as exc:
            log.warning(
                "database_scan_failed",
                scheme = scheme,
                error = str(exc),
            )
            result.errors.append(f"Database scan failed: {exc}")

        result.scan_completed_at = datetime.now(UTC)
        return result

    async def _scan_postgres(
        self,
        uri: str,
        result: ScanResult,
    ) -> None:
        """
        Scan PostgreSQL using asyncpg with TABLESAMPLE
        """
        import asyncpg

        conn = await asyncpg.connect(
            uri,
            timeout = self._db_config.timeout_seconds,
        )

        try:
            tables = await self._get_pg_tables(conn)
            tables = self._filter_tables(tables)

            for table_name in tables:
                text_cols = (
                    await self._get_pg_text_columns(conn,
                                                    table_name)
                )
                if not text_cols:
                    continue

                col_list = ", ".join(f'"{c}"' for c in text_cols)
                query = (
                    f"SELECT {col_list} "
                    f'FROM "{table_name}" '
                    f"TABLESAMPLE BERNOULLI("
                    f"{self._db_config.sample_percentage}"
                    f") LIMIT "
                    f"{self._db_config.max_rows_per_table}"
                )

                rows = await conn.fetch(query)
                self._process_record_rows(
                    rows,
                    text_cols,
                    table_name,
                    uri,
                    result,
                )
                result.targets_scanned += 1
        finally:
            await conn.close()

    async def _get_pg_tables(
        self,
        conn: Any,
    ) -> list[str]:
        """
        List user tables in PostgreSQL
        """
        rows = await conn.fetch(
            "SELECT table_name "
            "FROM information_schema.tables "
            "WHERE table_schema = 'public' "
            "AND table_type = 'BASE TABLE'"
        )
        return [r["table_name"] for r in rows]

    async def _get_pg_text_columns(
        self,
        conn: Any,
        table_name: str,
    ) -> list[str]:
        """
        Find text-type columns in a PostgreSQL table
        """
        rows = await conn.fetch(
            "SELECT column_name "
            "FROM information_schema.columns "
            "WHERE table_name = $1 "
            "AND data_type = ANY($2::text[])",
            table_name,
            list(TEXT_DB_COLUMN_TYPES_PG),
        )
        return [r["column_name"] for r in rows]

    async def _scan_mysql(
        self,
        uri: str,
        result: ScanResult,
    ) -> None:
        """
        Scan MySQL using aiomysql with random sampling
        """
        import aiomysql

        parsed = urlparse(uri)
        conn = await aiomysql.connect(
            host = parsed.hostname or "localhost",
            port = parsed.port or 3306,
            user = parsed.username or "root",
            password = parsed.password or "",
            db = parsed.path.lstrip("/"),
            connect_timeout = (self._db_config.timeout_seconds),
        )

        try:
            async with conn.cursor(aiomysql.DictCursor) as cur:
                await cur.execute(
                    "SELECT table_name "
                    "FROM information_schema.tables "
                    "WHERE table_schema = DATABASE() "
                    "AND table_type = 'BASE TABLE'"
                )
                raw_tables = await cur.fetchall()
                tables = [r["TABLE_NAME"] for r in raw_tables]
                tables = self._filter_tables(tables)

                for table_name in tables:
                    text_cols = (
                        await self._get_mysql_text_cols(cur,
                                                        table_name)
                    )
                    if not text_cols:
                        continue

                    col_list = ", ".join(f"`{c}`" for c in text_cols)
                    limit = (self._db_config.max_rows_per_table)
                    await cur.execute(
                        f"SELECT {col_list} "
                        f"FROM `{table_name}` "
                        f"ORDER BY RAND() "
                        f"LIMIT {limit}"
                    )
                    rows = await cur.fetchall()
                    self._process_dict_rows(
                        rows,
                        text_cols,
                        table_name,
                        uri,
                        result,
                    )
                    result.targets_scanned += 1
        finally:
            conn.close()

    async def _get_mysql_text_cols(
        self,
        cursor: Any,
        table_name: str,
    ) -> list[str]:
        """
        Find text-type columns in a MySQL table
        """
        placeholders = ",".join(["%s"] * len(TEXT_DB_COLUMN_TYPES_MYSQL))
        await cursor.execute(
            "SELECT column_name "
            "FROM information_schema.columns "
            "WHERE table_name = %s "
            "AND table_schema = DATABASE() "
            f"AND data_type IN ({placeholders})",
            (table_name,
             *TEXT_DB_COLUMN_TYPES_MYSQL),
        )
        rows = await cursor.fetchall()
        return [r["COLUMN_NAME"] for r in rows]

    async def _scan_mongodb(
        self,
        uri: str,
        result: ScanResult,
    ) -> None:
        """
        Scan MongoDB collections using pymongo async
        """
        from pymongo import AsyncMongoClient

        parsed = urlparse(uri)
        db_name = parsed.path.lstrip("/").split("?")[0]

        if not db_name:
            result.errors.append("MongoDB URI must include database name")
            return

        client: AsyncMongoClient[dict[str, Any]] = (AsyncMongoClient(uri))

        try:
            db = client[db_name]
            collections = (await db.list_collection_names())
            collections = self._filter_tables(collections)

            for coll_name in collections:
                coll = db[coll_name]
                sample_size = (self._db_config.max_rows_per_table)
                cursor = coll.aggregate(
                    [{
                        "$sample": {
                            "size": sample_size
                        }
                    }]
                )

                async for doc in cursor:
                    text_parts: list[str] = []
                    _extract_mongo_strings(doc, text_parts)
                    if not text_parts:
                        continue

                    combined = "\n".join(text_parts)
                    matches = self._registry.detect(combined)
                    self._append_findings(
                        matches,
                        combined,
                        table_name = coll_name,
                        uri = uri,
                        result = result,
                    )

                result.targets_scanned += 1
        finally:
            client.close()

    async def _scan_sqlite(
        self,
        uri: str,
        result: ScanResult,
    ) -> None:
        """
        Scan SQLite database using aiosqlite
        """
        import aiosqlite

        parsed = urlparse(uri)
        db_path = parsed.path
        while db_path.startswith("//"):
            db_path = db_path[1 :]

        async with aiosqlite.connect(db_path) as db:
            cursor = await db.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type = 'table' "
                "AND name NOT LIKE 'sqlite_%'"
            )
            rows = await cursor.fetchall()
            tables = [r[0] for r in rows]
            tables = self._filter_tables(tables)

            for table_name in tables:
                text_cols = (
                    await self._get_sqlite_text_cols(db,
                                                     table_name)
                )
                if not text_cols:
                    continue

                col_list = ", ".join(f'"{c}"' for c in text_cols)
                limit = (self._db_config.max_rows_per_table)
                cursor = await db.execute(
                    f"SELECT {col_list} "
                    f'FROM "{table_name}" '
                    f"ORDER BY RANDOM() "
                    f"LIMIT {limit}"
                )
                fetched = await cursor.fetchall()
                for row in fetched:
                    for idx, col_name in enumerate(text_cols):
                        val = row[idx]
                        if val is None:
                            continue
                        text = str(val)
                        if not text.strip():
                            continue
                        matches = self._registry.detect(text)
                        self._append_findings(
                            matches,
                            text,
                            table_name = table_name,
                            column_name = col_name,
                            uri = uri,
                            result = result,
                        )
                result.targets_scanned += 1

    async def _get_sqlite_text_cols(
        self,
        db: Any,
        table_name: str,
    ) -> list[str]:
        """
        Find text-type columns in a SQLite table
        """
        cursor = await db.execute(f'PRAGMA table_info("{table_name}")')
        rows = await cursor.fetchall()
        text_types = frozenset({"text", "varchar", "char", "clob"})
        return [
            r[1]
            for r in rows
            if r[2].lower() in text_types or "text" in r[2].lower()
        ]

    def _filter_tables(
        self,
        tables: list[str],
    ) -> list[str]:
        """
        Apply include/exclude table filters
        """
        include = self._db_config.include_tables
        exclude = frozenset(self._db_config.exclude_tables)

        if include:
            include_set = frozenset(include)
            tables = [t for t in tables if t in include_set]

        return [t for t in tables if t not in exclude]

    def _process_record_rows(
        self,
        rows: list[Any],
        columns: list[str],
        table_name: str,
        uri: str,
        result: ScanResult,
    ) -> None:
        """
        Process asyncpg Record rows through detection
        """
        for row in rows:
            for col_name in columns:
                val = row[col_name]
                if val is None:
                    continue
                text = str(val)
                if not text.strip():
                    continue
                matches = self._registry.detect(text)
                self._append_findings(
                    matches,
                    text,
                    table_name = table_name,
                    column_name = col_name,
                    uri = uri,
                    result = result,
                )

    def _process_dict_rows(
        self,
        rows: list[dict[str,
                        Any]],
        columns: list[str],
        table_name: str,
        uri: str,
        result: ScanResult,
    ) -> None:
        """
        Process dictionary rows through detection
        """
        for row in rows:
            for col_name in columns:
                val = row.get(col_name)
                if val is None:
                    continue
                text = str(val)
                if not text.strip():
                    continue
                matches = self._registry.detect(text)
                self._append_findings(
                    matches,
                    text,
                    table_name = table_name,
                    column_name = col_name,
                    uri = uri,
                    result = result,
                )

    def _append_findings(
        self,
        matches: list[DetectorMatch],
        text: str,
        table_name: str,
        uri: str,
        result: ScanResult,
        column_name: str = "",
    ) -> None:
        """
        Convert detector matches to findings and append
        """
        min_confidence = (self._detection_config.min_confidence)

        location = Location(
            source_type = "database",
            uri = uri,
            table_name = table_name,
            column_name = column_name or None,
        )

        for match in matches:
            if match.score < min_confidence:
                continue

            finding = match_to_finding(
                match,
                text,
                location,
                self._redaction_style,
            )
            result.findings.append(finding)


def _extract_mongo_strings(
    doc: dict[str,
              Any],
    parts: list[str],
    prefix: str = "",
) -> None:
    """
    Recursively extract string values from a MongoDB document
    """
    for key, val in doc.items():
        if key == "_id":
            continue
        key_path = (f"{prefix}.{key}" if prefix else key)
        if isinstance(val, str) and val.strip():
            parts.append(f"{key_path}: {val}")
        elif isinstance(val, dict):
            _extract_mongo_strings(val, parts, key_path)
        elif isinstance(val, list):
            for item in val:
                if (isinstance(item, str) and item.strip()):
                    parts.append(f"{key_path}: {item}")
                elif isinstance(item, dict):
                    _extract_mongo_strings(item, parts, key_path)
