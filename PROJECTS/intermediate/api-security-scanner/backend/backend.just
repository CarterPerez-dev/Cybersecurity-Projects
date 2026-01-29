# API Security Scanner Backend Commands
# AngelaMos | 2025

set dotenv-load
set export
set shell := ["bash", "-uc"]

# =============================================================================
# Setup (Local Development)
# =============================================================================

# Create venv and install all dependencies
[group('setup')]
setup:
    @echo "Creating virtual environment with uv..."
    uv venv
    uv sync --all-extras
    @echo "✓ Setup complete"

# Install dependencies
[group('setup')]
install:
    uv sync

# Reinstall all dependencies with upgrades
[group('setup')]
reinstall:
    uv lock --upgrade
    uv sync --all-extras

# =============================================================================
# Linting & Formatting
# =============================================================================

# Check all code for syntax issues (ruff)
[group('lint')]
check:
    @echo "======== Checking All Code ========"
    uv run ruff check .

# Fix all code syntax issues (ruff)
[group('lint')]
fix:
    @echo "======== Ruff Fix All Code ========"
    uv run ruff check . --fix

# In-depth linting (pylint)
[group('lint')]
pylint:
    @echo "======== Linting All Code ========"
    uv run pylint .

# Type checking (mypy)
[group('lint')]
mypy:
    @echo "======== Type Checking All Code ========"
    uv run mypy .

# Format code (yapf)
[group('lint')]
format:
    @echo "======== Formatting Code ========"
    uv run yapf -i -r -vv models/ repositories/ schemas/ scanners/ core/ factory/

# Run all quality checks
[group('lint')]
qa: check mypy
    @echo "✓ All quality checks passed"

# =============================================================================
# Utilities
# =============================================================================

# Clean cache files
[group('utility')]
clean:
    @echo "======== Cleaning Cache Files ========"
    find . -type f -name "*.pyc" -delete
    find . -type d -name "__pycache__" -delete
    find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
    find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
    find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
    find . -type f -name ".coverage" -delete
    @echo "✓ Cleaned"

# Display file tree
[group('utility')]
tree:
    @echo "======== File Tree ========"
    tree -I 'node_modules|.git|*.log|dist|build|*.cache|*.egg-info|context|.venv|*.env'

# Find all TODOs
[group('utility')]
todo:
    @echo "======== Looking for TODOs ========"
    find . -name "*.py" -print0 | xargs -0 uv run pylint --disable=all --enable=W0511 --msg-template='{path}:{line}:{column}: {msg_id}: {msg} ({symbol})' || true

# Lock dependencies
[group('utility')]
lock:
    uv lock

# Update dependencies
[group('utility')]
update:
    uv lock --upgrade
    uv sync --all-extras
