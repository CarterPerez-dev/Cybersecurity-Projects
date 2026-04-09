"""
©AngelaMos | 2026
__init__.py

Test suite package for the ai-threat-detection backend

Contains unit, integration, and end-to-end tests covering
the full stack: API endpoints, ingestion pipeline, feature
extraction, rule engine, ML training and inference,
ensemble scoring, ONNX export, model metadata persistence,
CLI commands, and GeoIP enrichment. Uses pytest-asyncio for
async tests, fakeredis for Redis isolation, and in-memory
SQLite via aiosqlite for database tests

Connects to:
  tests/conftest - shared fixtures for DB and HTTP client
"""
