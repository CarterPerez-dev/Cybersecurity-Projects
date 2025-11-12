# Makefile
# ⒸAngelaMos | 2025
# Alias commands to easily run commands (use this or package.json scripts)

.PHONY: help dev dev-build dev-down dev-logs prod prod-build prod-down prod-logs clean clean-all

help:
	@echo "API Security Scanner - Available Commands"
	@echo "=========================================="
	@echo ""
	@echo "Development:"
	@echo "  make dev          - Start development environment"
	@echo "  make dev-build    - Build and start development environment"
	@echo "  make dev-down     - Stop development environment"
	@echo "  make dev-logs     - View development logs (follow mode)"
	@echo ""
	@echo "Production:"
	@echo "  make prod         - Start production environment (detached)"
	@echo "  make prod-build   - Build and start production environment"
	@echo "  make prod-down    - Stop production environment"
	@echo "  make prod-logs    - View production logs (follow mode)"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean        - Stop all containers and remove volumes"
	@echo "  make clean-all    - Clean + remove all Docker images/cache"
	@echo ""

dev:
	docker compose -f docker-compose.dev.yml up

dev-build:
	docker compose -f docker-compose.dev.yml up --build

dev-down:
	docker compose -f docker-compose.dev.yml down

dev-logs:
	docker compose -f docker-compose.dev.yml logs -f

prod:
	docker compose -f docker-compose.prod.yml up -d

prod-build:
	docker compose -f docker-compose.prod.yml up --build -d

prod-down:
	docker compose -f docker-compose.prod.yml down

prod-logs:
	docker compose -f docker-compose.prod.yml logs -f

clean:
	docker compose -f docker-compose.dev.yml down -v
	docker compose -f docker-compose.prod.yml down -v

clean-all: clean
	docker system prune -af --volumes
