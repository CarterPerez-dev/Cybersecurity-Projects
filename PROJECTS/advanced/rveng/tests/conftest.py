"""
©AngelaMos | 2026
conftest.py
"""

from pathlib import Path

import pytest


FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope = "session")
def gate_path() -> Path:
    return FIXTURES / "gate"


@pytest.fixture(scope = "session")
def gate_bytes(gate_path: Path) -> bytes:
    return gate_path.read_bytes()


@pytest.fixture(scope = "session")
def gate_stripped_path() -> Path:
    return FIXTURES / "gate_stripped"


@pytest.fixture(scope = "session")
def gate_stripped_bytes(gate_stripped_path: Path) -> bytes:
    return gate_stripped_path.read_bytes()
