# ©AngelaMos | 2026
# justfile

set shell := ["bash", "-cu"]

binary := "nadezhda"

default:
    @just --list

build:
    go build -o {{binary}} ./cmd/nadezhda

run *args:
    go run ./cmd/nadezhda {{args}}

test:
    go test ./...

vet:
    go vet ./...

fmt:
    gofmt -w .

lint: vet
    test -z "$(gofmt -l .)"

tidy:
    go mod tidy

ollama-up:
    docker compose -f internal/setup/ollama.compose.yml up -d
    @echo "ollama starting on 127.0.0.1:39847 (override with OLLAMA_HOST_PORT) — the first run pulls qwen2.5:7b (a few minutes). watch progress with: just ollama-logs"

ollama-down:
    docker compose -f internal/setup/ollama.compose.yml down

ollama-logs:
    docker compose -f internal/setup/ollama.compose.yml logs -f

watch *args:
    go run ./cmd/nadezhda watch {{args}}

publish target="~/dev/nadezhda":
    rsync -a --delete \
      --exclude='.git/' --exclude='docs/' --exclude='/{{binary}}' \
      --exclude='*.db' --exclude='*.db-wal' --exclude='*.db-shm' \
      --exclude='/bin/' --exclude='*.test' --exclude='*.out' --exclude='*.prof' \
      --exclude='testdata/kev/kev-full.json' \
      ./ {{target}}/
    @echo "synced this project -> {{target}} (docs/ + build artifacts excluded)"
    @echo "review, then: cd {{target}} && git add -A && git commit && git push"

clean:
    rm -f {{binary}} *.db *.db-wal *.db-shm
