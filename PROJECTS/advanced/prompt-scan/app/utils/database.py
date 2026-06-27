"""
Prompt Scan — Database Utility
Author: mohelobeid (https://github.com/mohelobeid)
WARNING: Intentionally vulnerable — SQL injection throughout. LLM02/LLM06/LLM08
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime

from app.config import config


class VulnerableDatabase:
    def __init__(self) -> None:
        self.db_path = config.SQLALCHEMY_DATABASE_URI.replace("sqlite:///", "")
        self._ensure_db_dir()
        self._create_tables()
        self._seed_data()

    def _ensure_db_dir(self) -> None:
        db_dir = os.path.dirname(self.db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)

    def _get_connection(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def _create_tables(self) -> None:
        conn = self._get_connection()
        c = conn.cursor()
        c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, email TEXT, is_admin INTEGER DEFAULT 0, api_key TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
        c.execute("CREATE TABLE IF NOT EXISTS chat_history (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, message TEXT, response TEXT, tokens_used INTEGER DEFAULT 0, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
        c.execute("CREATE TABLE IF NOT EXISTS secrets (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, value TEXT, description TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
        conn.commit()
        conn.close()

    def _seed_data(self) -> None:
        conn = self._get_connection()
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM users")
        if c.fetchone()[0] == 0:
            c.executemany("INSERT INTO users (username, password, email, is_admin, api_key) VALUES (?,?,?,?,?)",
                [("admin","password123","admin@lab.local",1,"admin-api-key-abc123"),
                 ("alice","alice123","alice@lab.local",0,"alice-api-key-xyz789"),
                 ("bob","bob456","bob@lab.local",0,"bob-api-key-def456")])
        c.execute("SELECT COUNT(*) FROM secrets")
        if c.fetchone()[0] == 0:
            c.executemany("INSERT INTO secrets (name, value, description) VALUES (?,?,?)",
                [("DATABASE_PASSWORD","super_secret_db_pass","Production database password"),
                 ("API_KEY","sk-real-prod-key-12345","Production OpenAI API key"),
                 ("JWT_SECRET","jwt-signing-secret-9876","JWT signing key"),
                 ("ADMIN_TOKEN","admin-bearer-token-xyz","Admin API bearer token")])
        conn.commit()
        conn.close()

    def _rows(self, cursor) -> list[dict]:
        rows = cursor.fetchall()
        cols = [d[0] for d in cursor.description] if cursor.description else []
        return [dict(zip(cols, r)) for r in rows]

    def get_all_users(self) -> dict:
        conn = self._get_connection(); c = conn.cursor()
        c.execute("SELECT * FROM users")
        result = self._rows(c); conn.close()
        return {"users": result, "count": len(result)}

    def get_user_by_id(self, user_id: str) -> dict:
        conn = self._get_connection(); c = conn.cursor()
        query = f"SELECT * FROM users WHERE id = {user_id}"  # noqa: S608
        try:
            c.execute(query); row = c.fetchone()
            cols = [d[0] for d in c.description]; conn.close()
            return {"user": dict(zip(cols, row)) if row else None, "query": query}
        except sqlite3.OperationalError as exc:
            conn.close(); return {"error": str(exc), "query": query}

    def search_users(self, search_term: str) -> dict:
        conn = self._get_connection(); c = conn.cursor()
        query = f"SELECT * FROM users WHERE username LIKE '%{search_term}%'"  # noqa: S608
        try:
            c.execute(query); result = self._rows(c); conn.close()
            return {"results": result, "count": len(result), "query": query}
        except sqlite3.OperationalError as exc:
            conn.close(); return {"error": str(exc), "query": query}

    def update_user(self, user_id: str, field: str, value: str) -> dict:
        conn = self._get_connection(); c = conn.cursor()
        query = f"UPDATE users SET {field} = '{value}' WHERE id = {user_id}"  # noqa: S608
        try:
            c.execute(query); conn.commit(); conn.close()
            return {"success": True, "query": query, "rows_affected": c.rowcount}
        except sqlite3.OperationalError as exc:
            conn.close(); return {"error": str(exc), "query": query}

    def delete_user(self, user_id: str) -> dict:
        conn = self._get_connection(); c = conn.cursor()
        query = f"DELETE FROM users WHERE id = {user_id}"  # noqa: S608
        try:
            c.execute(query); conn.commit(); conn.close()
            return {"success": True, "deleted_id": user_id, "rows_affected": c.rowcount}
        except sqlite3.OperationalError as exc:
            conn.close(); return {"error": str(exc)}

    def get_secrets(self) -> dict:
        conn = self._get_connection(); c = conn.cursor()
        c.execute("SELECT * FROM secrets"); result = self._rows(c); conn.close()
        return {"secrets": result}

    def execute_raw_sql(self, query: str) -> dict:
        conn = self._get_connection(); c = conn.cursor()
        try:
            c.execute(query)
            try:
                result = self._rows(c); conn.commit(); conn.close()
                return {"success": True, "rows": result, "row_count": len(result), "query": query}
            except Exception:  # pylint: disable=broad-exception-caught
                conn.commit(); conn.close()
                return {"success": True, "rows_affected": c.rowcount, "query": query}
        except sqlite3.OperationalError as exc:
            conn.close(); return {"success": False, "error": str(exc), "query": query}

    def get_database_schema(self) -> dict:
        conn = self._get_connection(); c = conn.cursor()
        c.execute("SELECT name, sql FROM sqlite_master WHERE type='table'")
        tables = c.fetchall(); conn.close()
        return {"tables": [{"name": t[0], "schema": t[1]} for t in tables]}

    def get_database_info(self) -> dict:
        return {"db_path": self.db_path,
                "db_size_bytes": os.path.getsize(self.db_path) if os.path.exists(self.db_path) else 0}

    def get_chat_history(self, user_id: str | None = None) -> dict:
        conn = self._get_connection(); c = conn.cursor()
        if user_id:
            c.execute("SELECT * FROM chat_history WHERE user_id = ?", (user_id,))
        else:
            c.execute("SELECT * FROM chat_history")
        result = self._rows(c); conn.close()
        return {"history": result, "count": len(result)}

    def save_chat(self, user_id: int, message: str, response: str, tokens_used: int) -> dict:
        conn = self._get_connection(); c = conn.cursor()
        c.execute("INSERT INTO chat_history (user_id, message, response, tokens_used, timestamp) VALUES (?,?,?,?,?)",
                  (user_id, message, response, tokens_used, datetime.utcnow().isoformat()))
        conn.commit(); record_id = c.lastrowid; conn.close()
        return {"success": True, "id": record_id}


db = VulnerableDatabase()
