# =============================================================================
# AngelaMos | 2025
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
    uv run dnslookup {{ARGS}}

[group('run')]
lookup domain *ARGS:
    uv run dnslookup {{domain}} {{ARGS}}

[group('run')]
reverse ip:
    uv run dnslookup reverse {{ip}}

[group('run')]
trace domain:
    uv run dnslookup trace {{domain}}

[group('run')]
batch file *ARGS:
    uv run dnslookup batch {{file}} {{ARGS}}

[group('run')]
whois domain:
    uv run dnslookup whois {{domain}}

# =============================================================================
# Linting and Formatting
# =============================================================================

[group('lint')]
ruff *ARGS:
    uv run ruff check dnslookup/ {{ARGS}}

[group('lint')]
ruff-fix:
    uv run ruff check dnslookup/ --fix
    uv run ruff format dnslookup/

[group('lint')]
ruff-format:
    uv run ruff format dnslookup/

[group('lint')]
lint: ruff

# =============================================================================
# Type Checking
# =============================================================================

[group('types')]
mypy *ARGS:
    uv run mypy dnslookup/ {{ARGS}}

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
    uv run pytest --cov=dnslookup --cov-report=term-missing --cov-report=html

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
