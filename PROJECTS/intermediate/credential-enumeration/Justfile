# =============================================================================
# ©AngelaMos | 2026
# Justfile
# =============================================================================
# credenum — Post-access credential exposure detection for Linux systems
# =============================================================================

set export
set shell := ["bash", "-uc"]

bin     := "bin/credenum"
src     := "src/harvester.nim"
version := `git describe --tags --always 2>/dev/null || echo "dev"`

# =============================================================================
# Default
# =============================================================================

default:
    @just --list --unsorted

# =============================================================================
# Development
# =============================================================================

[group('dev')]
build:
    @mkdir -p bin
    nim c -o:{{bin}} {{src}}
    @echo "Built: {{bin}} ($(du -h {{bin}} | cut -f1))"

[group('dev')]
run *ARGS: build
    ./{{bin}} {{ARGS}}

[group('dev')]
scan *ARGS: build
    ./{{bin}} --target $HOME {{ARGS}}

[group('dev')]
check:
    nim check {{src}}

# =============================================================================
# Build (Production)
# =============================================================================

[group('prod')]
release:
    @mkdir -p bin
    nim c -d:release -d:lto --opt:size -o:{{bin}} {{src}}
    strip -s {{bin}} 2>/dev/null || true
    @echo "Release: {{bin}} ($(du -h {{bin}} | cut -f1))"

[group('prod')]
release-static:
    @mkdir -p bin
    nim c -d:release -d:musl -d:lto --opt:size -o:{{bin}} {{src}}
    strip -s {{bin}} 2>/dev/null || true
    @echo "Static release: {{bin}} ($(du -h {{bin}} | cut -f1))"

[group('prod')]
release-small: release-static
    upx --best {{bin}}
    @echo "Compressed: {{bin}} ($(du -h {{bin}} | cut -f1))"

[group('prod')]
build-x86:
    @mkdir -p bin
    nim c -d:release -d:zigcc -d:crossX86 -d:lto --opt:size -o:bin/credenum-x86_64 {{src}}
    @echo "Cross-compiled: bin/credenum-x86_64"

[group('prod')]
build-arm64:
    @mkdir -p bin
    nim c -d:release -d:zigcc -d:crossArm64 -d:lto --opt:size -o:bin/credenum-aarch64 {{src}}
    @echo "Cross-compiled: bin/credenum-aarch64"

# =============================================================================
# Testing
# =============================================================================

[group('test')]
test:
    nim c -r --path:src tests/test_all.nim

[group('test')]
docker-build:
    docker build -t credenum-test -f tests/docker/Dockerfile .

[group('test')]
docker-test: docker-build
    docker run --rm credenum-test

# =============================================================================
# Formatting
# =============================================================================

[group('lint')]
fmt:
    nph src/

[group('lint')]
fmt-check:
    nph --check src/

# =============================================================================
# Utilities
# =============================================================================

[group('util')]
info:
    @echo "Project:  credential-enumeration"
    @echo "Version:  {{version}}"
    @echo "Nim:      $(nim --version | head -1)"
    @echo "OS:       {{os()}} ({{arch()}})"
    @echo "Binary:   {{bin}}"
    @test -f {{bin}} && echo "Size:     $(du -h {{bin}} | cut -f1)" || echo "Size:     (not built)"

[group('util')]
clean:
    -rm -rf bin/ nimcache/
    -find . -name "nimcache" -type d -exec rm -rf {} + 2>/dev/null
    @echo "Cleaned build artifacts."
