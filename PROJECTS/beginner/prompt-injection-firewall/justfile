# ©AngelaMos | 2026
# justfile

set shell := ["bash", "-uc"]

default:
    @just --list

lint:
    uv run ruff check .
    uv run mypy src/ tests/ bench/

format:
    uv run yapf -r -i src/ tests/ bench/

check-format:
    uv run yapf -r -d src/ tests/ bench/

test:
    uv run pytest tests/ -v

bench:
    uv run python -m bench.runner

check: lint check-format test

ui-lint:
    cd frontend && pnpm lint && pnpm lint:scss

ui-typecheck:
    cd frontend && pnpm typecheck

ui-build:
    cd frontend && pnpm build

ui-check: ui-lint ui-typecheck ui-build

check-all: check ui-check

arena:
    docker compose -f compose.yml --env-file .env up -d --build

arena-down:
    docker compose -f compose.yml --env-file .env down

arena-logs:
    docker compose -f compose.yml --env-file .env logs -f

arena-dev:
    docker compose -f dev.compose.yml --env-file .env.development \
        up --build

arena-dev-down:
    docker compose -f dev.compose.yml --env-file .env.development down

tunnel:
    docker compose -f compose.yml -f cloudflared.compose.yml \
        --env-file .env up -d --build

tunnel-down:
    docker compose -f compose.yml -f cloudflared.compose.yml \
        --env-file .env down

audit-tail:
    docker compose -f compose.yml --env-file .env exec arena \
        tail -n 20 /var/lib/not-sandboxed/audit.jsonl

bypasses-export dest="bypasses.jsonl":
    docker compose -f compose.yml --env-file .env exec -T arena \
        cat /var/lib/not-sandboxed/bypasses.jsonl > {{dest}}

harvest source="bypasses.jsonl" root="bench/corpus":
    uv run python -m not_sandboxed.arena.harvest {{source}} {{root}}
