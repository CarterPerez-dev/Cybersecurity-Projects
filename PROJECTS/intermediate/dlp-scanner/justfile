# ©AngelaMos | 2026
# justfile

default:
    @just --list

lint:
    uv run ruff check .
    uv run mypy src/

format:
    uv run yapf -r -i src/ tests/

check-format:
    uv run yapf -r -d src/ tests/

test:
    uv run pytest tests/ -m "unit"

test-all:
    uv run pytest tests/

run *ARGS:
    uv run dlp-scan {{ARGS}}

install:
    bash install.sh
