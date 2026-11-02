# =============================================================================
# ©AngelaMos | 2026
# canary.dev.dockerfile
# =============================================================================
# Development image: golang:1.25-alpine + Air for hot reload.
# Source is bind-mounted by dev.compose.yml; Air rebuilds on file change.
#
# Build context: ./backend
# Reads .air.toml from the bind-mounted source.
# =============================================================================

FROM golang:1.25-alpine

RUN apk add --no-cache git curl wget

RUN go install github.com/air-verse/air@latest

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

EXPOSE 8080

CMD ["air", "-c", ".air.toml"]
