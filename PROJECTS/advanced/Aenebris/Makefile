# Ᾰenebris Makefile - Common development commands

.PHONY: help build run logs stop restart clean test backend kill-all

help:
	@echo "Ᾰenebris Development Commands:"
	@echo ""
	@echo "  make build       - Build the project"
	@echo "  make run         - Start Ᾰenebris proxy"
	@echo "  make logs        - Watch logs in real-time"
	@echo "  make stop        - Stop the proxy"
	@echo "  make restart     - Restart the proxy"
	@echo "  make clean       - Clean build artifacts"
	@echo ""
	@echo "  make backend     - Start test backend (port 8000)"
	@echo "  make test        - Run tests (when implemented)"
	@echo "  make kill-all    - Kill proxy + backend"
	@echo ""

build:
	@echo "Building Ᾰenebris..."
	@stack build

run:
	@echo "Starting Ᾰenebris on port 8081..."
	@nohup stack run examples/config.yaml > aenebris.log 2>&1 &
	@sleep 2
	@echo "Proxy started! PID: $$(pgrep -f 'aenebris examples' | head -1)"
	@echo "Run 'make logs' to watch output"

logs:
	@echo "Watching Ᾰenebris logs (Ctrl+C to exit)..."
	@tail -f aenebris.log

stop:
	@echo "Stopping Ᾰenebris..."
	@pkill -f 'aenebris examples' || echo "Proxy not running"

restart: stop
	@sleep 1
	@make run

clean:
	@echo "Cleaning build artifacts..."
	@stack clean
	@rm -f aenebris.log nohup.out

backend:
	@echo "Starting test backend on port 8000..."
	@python3 examples/test_backend.py > backend.log 2>&1 &
	@sleep 1
	@echo "Backend started! PID: $$(pgrep -f test_backend | head -1)"

# Run tests (placeholder for now)
test:
	@echo "Running tests..."
	@stack test

kill-all:
	@echo "Killing all processes..."
	@pkill -f 'aenebris examples' || echo "Proxy not running"
	@pkill -f test_backend || echo "Backend not running"
	@echo "All processes stopped"
