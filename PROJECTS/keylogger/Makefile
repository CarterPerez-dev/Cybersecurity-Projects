# CarterPerez-dev | 2025
# Makefile

.PHONY: help venv setup install install-dev test lint format clean all

help:
	@echo "Keylogger - Makefile Commands"
	@echo "=========================================="
	@echo ""
	@echo "Setup Commands:"
	@echo "  make setup         - Create venv and install dependencies"
	@echo "  make install       - Install project dependencies only"
	@echo "  make install-dev   - Install with dev tools (linters, formatters)"
	@echo ""
	@echo "Testing & Quality:"
	@echo "  make test          - Run test suite"
	@echo "  make lint          - Run all linting checks (ruff, pylint, mypy)"
	@echo "  make format        - Format code with yapf"
	@echo ""
	@echo "Utility:"
	@echo "  make clean         - Remove venv and cache files"
	@echo "  make all           - Setup, test, and lint everything"
	@echo ""

venv:
	@echo "Creating virtual environment..."
	python -m venv venv
	@echo "Virtual environment created at ./venv"
	@echo ""
	@echo "Activate with:"
	@echo "  source venv/bin/activate  (Linux/macOS)"
	@echo "  venv\\Scripts\\activate    (Windows)"

setup: venv
	@echo ""
	@echo "Installing dependencies..."
	./venv/bin/pip install --upgrade pip
	./venv/bin/pip install -e ".[dev]"
	@echo "✓ Setup complete!"
	@echo ""
	@echo "Run tests with: make test"

install:
	@echo "Installing main dependencies..."
	pip install -e .
	@echo "Dependencies installed"

install-dev:
	@echo "Installing with dev dependencies..."
	pip install -e ".[dev]"
	@echo "Dev dependencies installed"

test:
	@echo "Running tests..."
	@echo ""
	python test_keylogger.py

lint:
	@echo "Running linting checks..."
	@echo ""
	@echo "=== Ruff ==="
	ruff check keylogger.py
	@echo ""
	@echo "=== Pylint ==="
	pylint keylogger.py
	@echo ""
	@echo "=== Mypy ==="
	mypy keylogger.py
	@echo ""
	@echo "All linting checks passed!"

format:
	@echo "Formatting code with yapf..."
	yapf -i keylogger.py test_keylogger.py
	@echo "Code formatted"

clean:
	@echo "Cleaning up..."
	rm -rf venv
	rm -rf __pycache__
	rm -rf *.pyc
	rm -rf .mypy_cache
	rm -rf .ruff_cache
	rm -rf .pytest_cache
	rm -rf *.egg-info
	rm -rf build
	rm -rf dist
	@echo "Cleaned"

# Do everything: setup, test, lint
all: setup test lint
	@echo ""
	@echo "=========================================="
	@echo "Everything complete!"
	@echo "=========================================="
