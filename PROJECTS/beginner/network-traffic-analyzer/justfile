# =============================================================================
# ⒸAngelaMos | 2026 | 2026
# justfile
# =============================================================================

set dotenv-load
set export
set shell := ["bash", "-uc"]
set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

project := file_name(justfile_directory())
version := `git describe --tags --always 2>/dev/null || echo "dev"`

# =============================================================================
# Default
# =============================================================================

default:
    @just --list --unsorted

# =============================================================================
# Run
# =============================================================================

[group('run')]
run *ARGS:
    uv run netanal {{ARGS}}

[group('run')]
capture *ARGS:
    uv run netanal capture {{ARGS}}

[group('run')]
analyze file *ARGS:
    uv run netanal analyze {{file}} {{ARGS}}

[group('run')]
stats file *ARGS:
    uv run netanal stats {{file}} {{ARGS}}

[group('run')]
export file *ARGS:
    uv run netanal export {{file}} {{ARGS}}

[group('run')]
chart file *ARGS:
    uv run netanal chart {{file}} {{ARGS}}

[group('run')]
interfaces:
    uv run netanal interfaces

# =============================================================================
# Linting and Formatting
# =============================================================================

[group('lint')]
ruff *ARGS:
    uv run ruff check src/netanal/ {{ARGS}}

[group('lint')]
ruff-fix:
    uv run ruff check src/netanal/ --fix
    uv run ruff format src/netanal/

[group('lint')]
ruff-format:
    uv run ruff format src/netanal/

[group('lint')]
lint: ruff

# =============================================================================
# Type Checking
# =============================================================================

[group('types')]
mypy *ARGS:
    uv run mypy src/netanal/ {{ARGS}}

[group('types')]
typecheck: mypy

# =============================================================================
# Testing
# =============================================================================

[group('test')]
test *ARGS:
    uv run pytest {{ARGS}}

[group('test')]
test-cov:
    uv run pytest --cov=netanal --cov-report=term-missing --cov-report=html

# =============================================================================
# CI / Quality
# =============================================================================

[group('ci')]
ci: lint typecheck test

[group('ci')]
check: ruff mypy

# =============================================================================
# Setup
# =============================================================================

[group('setup')]
setup:
    uv sync --all-extras

[group('setup')]
install:
    uv sync

[group('setup')]
install-dev:
    uv sync --all-extras

# =============================================================================
# Utilities
# =============================================================================

[group('util')]
info:
    @echo "Project: {{project}}"
    @echo "Version: {{version}}"
    @echo "OS: {{os()}} ({{arch()}})"

[group('util')]
clean:
    -rm -rf .mypy_cache
    -rm -rf .pytest_cache
    -rm -rf .ruff_cache
    -rm -rf htmlcov
    -rm -rf .coverage
    -rm -rf dist
    -rm -rf *.egg-info
    @echo "Cache directories cleaned"
