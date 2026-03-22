# ©AngelaMos | 2026
# Justfile

set shell := ["bash", "-uc"]

default:
    @just --list --unsorted

build:
    cmake --preset debug
    cmake --build build/debug

release:
    cmake --preset release
    cmake --build build/release

run *ARGS:
    ./build/release/hashcracker {{ARGS}}

run-debug *ARGS:
    ./build/debug/hashcracker {{ARGS}}

test:
    cmake --preset debug
    cmake --build build/debug
    ctest --test-dir build/debug --output-on-failure

clean:
    rm -rf build/
