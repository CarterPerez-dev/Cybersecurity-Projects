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
    uv run pytest tests/ -m "not integration"

test-all:
    sudo uv run pytest tests/

run *ARGS:
    sudo uv run ebpf-tracer {{ARGS}}

install:
    ./install.sh
