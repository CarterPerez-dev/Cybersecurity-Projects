# ⒸAngelaMos | 2026

default:
    @just --list

install:
    uv sync --all-extras

dev-install:
    uv sync --dev --all-extras

test:
    uv run pytest tests/ -v

lint:
    uv run ruff check src/ tests/

lint-fix:
    uv run ruff check --fix src/ tests/

format:
    uv run ruff format src/ tests/

typecheck:
    uv run mypy src/

typecheck-ty:
    uv run ty check

check-all: lint typecheck test

clean:
    rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage
    find . -type d -name __pycache__ -exec rm -rf {} +
    find . -type f -name "*.pyc" -delete

encrypt TEXT KEY="3":
    uv run caesar-cipher encrypt "{{TEXT}}" --key {{KEY}}

decrypt TEXT KEY="3":
    uv run caesar-cipher decrypt "{{TEXT}}" --key {{KEY}}

crack TEXT:
    uv run caesar-cipher crack "{{TEXT}}"
