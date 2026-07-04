# =============================================================================
# ©AngelaMos | 2026
# justfile
# =============================================================================

set shell := ["bash", "-uc"]

project := file_name(justfile_directory())
version := `git describe --tags --always 2>/dev/null || echo "dev"`
bin     := justfile_directory() / "zig-out/bin/zingela"

# =============================================================================
# Default
# =============================================================================

default:
    @just --list --unsorted

# =============================================================================
# Build  (plain zig build is Debug; the shipped artifact is ReleaseSafe)
# =============================================================================

[group('build')]
build:
    zig build

[group('build')]
safe:
    zig build -Doptimize=ReleaseSafe

[group('build')]
fast:
    zig build -Doptimize=ReleaseFast

# ReleaseSafe with the AF_XDP TX backend compiled in
[group('build')]
xdp:
    zig build -Doptimize=ReleaseSafe -Dxdp=true

# static musl binaries for every distribution target -> zig-out/release/
[group('build')]
dist:
    zig build release

# =============================================================================
# Test
# =============================================================================

[group('test')]
test:
    zig build test

[group('test')]
test-verbose:
    zig build test --summary all

# the full matrix: Debug + ReleaseSafe, each with and without -Dxdp
[group('test')]
test-all:
    zig build test --summary all
    zig build test -Doptimize=ReleaseSafe --summary all
    zig build test -Dxdp=true --summary all
    zig build test -Doptimize=ReleaseSafe -Dxdp=true --summary all

# =============================================================================
# Bench
# =============================================================================

# hot-path microbenchmarks, ReleaseFast, measured on this host
[group('bench')]
bench:
    zig build bench

# =============================================================================
# Run
# =============================================================================

# run the built binary with any args, e.g. `just run --help`
[group('run')]
run *ARGS: build
    {{bin}} {{ARGS}}

# SYN/UDP scan; pass flags, e.g. `just scan --target 192.0.2.0/24 --ports 80`
[group('run')]
scan *ARGS: build
    {{bin}} scan {{ARGS}}

# grant raw-socket caps so scans run without sudo (reapply after every rebuild)
[group('run')]
setcap: build
    sudo setcap cap_net_raw,cap_net_admin=eip {{bin}}

# AF_PACKET ground-truth smoke on the installed binary (needs caps: run `just setcap`)
[group('run')]
smoke:
    zig build smoke

# =============================================================================
# Lint and Format
# =============================================================================

[group('lint')]
fmt:
    zig fmt build.zig build.zig.zon src

[group('lint')]
fmt-check:
    zig fmt --check build.zig build.zig.zon src

# =============================================================================
# Install
# =============================================================================

# one-shot install to PATH + setcap (prebuilt-first, source fallback)
[group('install')]
install:
    ./install.sh

[group('install')]
uninstall:
    ./uninstall.sh

# =============================================================================
# CI / Quality  (the always-green gate; fmt-check and smoke are separate:
#   smoke needs raw-socket caps, and fmt has pre-existing debt to clear)
# =============================================================================

[group('ci')]
ci: build test

# =============================================================================
# Utilities
# =============================================================================

[group('util')]
info:
    @echo "Project: {{project}}"
    @echo "Version: {{version}}"
    @echo "Binary:  {{bin}}"
    @echo "OS:      {{os()}} ({{arch()}})"
    @zig version | xargs -I{} echo "Zig:     {}"

[group('util')]
clean:
    -rm -rf zig-out
    -rm -rf .zig-cache
    @echo "Build artifacts cleaned"
