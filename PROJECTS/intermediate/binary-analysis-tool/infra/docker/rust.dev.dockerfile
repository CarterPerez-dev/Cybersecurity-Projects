# ©AngelaMos | 2026
# rust.dev.dockerfile
# Development Dockerfile for Rust backend with cargo-watch hot reload
# syntax=docker/dockerfile:1

FROM rust:1.88-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        pkg-config libssl-dev libpq-dev && \
    rm -rf /var/lib/apt/lists/* && \
    cargo install cargo-watch

WORKDIR /app

EXPOSE 3000

CMD ["cargo", "watch", "-x", "run", "-w", "crates"]
