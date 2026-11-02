# =============================================================================
# ©AngelaMos | 2026
# tlsfp.prod.dockerfile
# =============================================================================
# Production Dockerfile: builds the tlsfp binary, ships a slim runtime.
# The pcap crate links libpcap, so the builder needs libpcap-dev and the
# runtime needs libpcap0.8. rusqlite is bundled, so no system SQLite.
# =============================================================================
# syntax=docker/dockerfile:1

# ============================================================================
# BUILD STAGE
# ============================================================================
FROM rust:1-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release --bin tlsfp \
    && cp target/release/tlsfp /usr/local/bin/tlsfp \
    && strip /usr/local/bin/tlsfp

# ============================================================================
# RUNTIME STAGE
# ============================================================================
FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap0.8 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --no-create-home tlsfp \
    && mkdir -p /data /demo \
    && chown tlsfp:tlsfp /data

COPY --from=builder /usr/local/bin/tlsfp /usr/local/bin/tlsfp

# A vendored capture the demo command replays so the dashboard is alive on boot.
COPY testdata/pcap/tls-alpn-h2.pcap /demo/demo.pcap

USER tlsfp
WORKDIR /data

EXPOSE 8080

ENTRYPOINT ["tlsfp"]
CMD ["serve", "0.0.0.0:8080"]
