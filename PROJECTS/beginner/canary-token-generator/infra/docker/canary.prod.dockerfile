# =============================================================================
# ©AngelaMos | 2026
# canary.prod.dockerfile
# =============================================================================
# Multi-stage build:
#   Stage 1 (builder)   golang:1.25-alpine, CGO_ENABLED=0, trimpath, ldflags
#   Stage 2 (final)     gcr.io/distroless/static:nonroot — no shell, non-root
#
# Build context: ./backend (set by compose.yml)
# Result: /canary single static binary, runs as nonroot user.
# =============================================================================

FROM golang:1.25-alpine AS builder

RUN apk add --no-cache ca-certificates git

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/canary \
    ./cmd/canary

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/healthcheck \
    ./cmd/healthcheck

FROM gcr.io/distroless/static:nonroot AS final

WORKDIR /

COPY --from=builder /out/canary /canary
COPY --from=builder /out/healthcheck /healthcheck
COPY --from=builder /src/config.yaml /config.yaml

EXPOSE 8080
USER nonroot:nonroot

ENTRYPOINT ["/canary"]
CMD ["-config", "/config.yaml"]
