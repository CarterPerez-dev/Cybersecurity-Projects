# ©AngelaMos | 2026
# rust.prod.dockerfile
# Production multi-stage Dockerfile for Rust backend
# syntax=docker/dockerfile:1

# ============================================================================
# BUILD STAGE
# ============================================================================
FROM rust:1.88-slim AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        pkg-config libssl-dev libpq-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY backend/Cargo.toml backend/Cargo.lock* ./
COPY backend/crates ./crates

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release && \
    cp target/release/axumortem /usr/local/bin/axumortem

# ============================================================================
# RUNTIME STAGE
# ============================================================================
FROM debian:bookworm-slim AS runtime

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libpq5 ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    useradd --create-home --shell /bin/false axumortem

COPY --from=builder /usr/local/bin/axumortem /usr/local/bin/axumortem

USER axumortem

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/axumortem", "--help"]

ENTRYPOINT ["/usr/local/bin/axumortem"]
