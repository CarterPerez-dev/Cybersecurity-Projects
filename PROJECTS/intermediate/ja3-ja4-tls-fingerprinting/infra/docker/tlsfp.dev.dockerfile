# =============================================================================
# ©AngelaMos | 2026
# tlsfp.dev.dockerfile
# =============================================================================
# Development Dockerfile: toolchain plus cargo-watch, source mounted at runtime.
# The compose service mounts the workspace at /workspace and a cached target
# volume, so this image only provides the build environment, not the code.
# =============================================================================
# syntax=docker/dockerfile:1

FROM rust:1-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

RUN cargo install cargo-watch

WORKDIR /workspace

EXPOSE 8080

CMD ["cargo", "watch", "-x", "run --bin tlsfp -- serve 0.0.0.0:8080"]
