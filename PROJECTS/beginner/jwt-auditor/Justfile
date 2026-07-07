default:
    @just --list

install:
    uv sync --all-extras

test:
    uv run pytest tests/ -v

cov:
    uv run pytest tests/ --cov=jwt_auditor --cov-report=term-missing

lint:
    uv run ruff check src/ tests/

lint-fix:
    uv run ruff check --fix src/ tests/

typecheck:
    uv run mypy src/

check-all: lint typecheck test

clean:
    rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage
    find . -type d -name __pycache__ -exec rm -rf {} +
    find . -type f -name "*.pyc" -delete

# Audit a token with the built in checks
audit TOKEN:
    uv run jwt-auditor audit "{{TOKEN}}"

# Decode a token without verifying it
decode TOKEN:
    uv run jwt-auditor decode "{{TOKEN}}"
